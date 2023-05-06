package bluetooth

import (
	"fmt"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/saltosystems/winrt-go"
	"github.com/saltosystems/winrt-go/windows/devices/bluetooth"
	"github.com/saltosystems/winrt-go/windows/devices/bluetooth/advertisement"
	"github.com/saltosystems/winrt-go/windows/devices/bluetooth/genericattributeprofile"
	"github.com/saltosystems/winrt-go/windows/devices/enumeration"
	"github.com/saltosystems/winrt-go/windows/foundation"
	"github.com/saltosystems/winrt-go/windows/storage/streams"
)

// Address contains a Bluetooth MAC address.
type Address struct {
	MACAddress
}

// Scan starts a BLE scan. It is stopped by a call to StopScan. A common pattern
// is to cancel the scan when a particular device has been found.
func (a *Adapter) Scan(callback func(*Adapter, ScanResult)) (err error) {
	if a.watcher != nil {
		// Cannot scan more than once: which one should ScanStop()
		// stop?
		return errScanning
	}

	a.watcher, err = advertisement.NewBluetoothLEAdvertisementWatcher()
	if err != nil {
		return
	}
	defer func() {
		_ = a.watcher.Release()
		a.watcher = nil
	}()

	// Set scanning mode to active so we receive scan responses
	// from devices in advertising mode
	err = a.watcher.SetScanningMode(advertisement.BluetoothLEScanningModeActive)
	if err != nil {
		return
	}

	// Listen for incoming BLE advertisement packets.
	// We need a TypedEventHandler<TSender, TResult> to listen to events, but since this is a parameterized delegate
	// its GUID depends on the classes used as sender and result, so we need to compute it:
	// TypedEventHandler<BluetoothLEAdvertisementWatcher, BluetoothLEAdvertisementReceivedEventArgs>
	eventReceivedGuid := winrt.ParameterizedInstanceGUID(
		foundation.GUIDTypedEventHandler,
		advertisement.SignatureBluetoothLEAdvertisementWatcher,
		advertisement.SignatureBluetoothLEAdvertisementReceivedEventArgs,
	)
	handler := foundation.NewTypedEventHandler(ole.NewGUID(eventReceivedGuid), func(instance *foundation.TypedEventHandler, sender, arg unsafe.Pointer) {
		args := (*advertisement.BluetoothLEAdvertisementReceivedEventArgs)(arg)
		result := getScanResultFromArgs(args)
		callback(a, result)
	})
	defer handler.Release()

	token, err := a.watcher.AddReceived(handler)
	if err != nil {
		return
	}
	defer a.watcher.RemoveReceived(token)

	// Wait for when advertisement has stopped by a call to StopScan().
	// Advertisement doesn't seem to stop right away, there is an
	// intermediate Stopping state.
	stoppingChan := make(chan struct{})
	// TypedEventHandler<BluetoothLEAdvertisementWatcher, BluetoothLEAdvertisementWatcherStoppedEventArgs>
	eventStoppedGuid := winrt.ParameterizedInstanceGUID(
		foundation.GUIDTypedEventHandler,
		advertisement.SignatureBluetoothLEAdvertisementWatcher,
		advertisement.SignatureBluetoothLEAdvertisementWatcherStoppedEventArgs,
	)
	stoppedHandler := foundation.NewTypedEventHandler(ole.NewGUID(eventStoppedGuid), func(_ *foundation.TypedEventHandler, _, _ unsafe.Pointer) {
		// Note: the args parameter has an Error property that should
		// probably be checked, but I'm not sure when stopping the
		// advertisement watcher could ever result in an error (except
		// for bugs).
		close(stoppingChan)
	})
	defer stoppedHandler.Release()

	token, err = a.watcher.AddStopped(stoppedHandler)
	if err != nil {
		return
	}
	defer a.watcher.RemoveStopped(token)

	err = a.watcher.Start()
	if err != nil {
		return err
	}

	// Wait until advertisement has stopped, and finish.
	<-stoppingChan
	return nil
}

func getScanResultFromArgs(args *advertisement.BluetoothLEAdvertisementReceivedEventArgs) ScanResult {
	// parse bluetooth address
	addr, _ := args.GetBluetoothAddress()
	adr := Address{}
	for i := range adr.MAC {
		adr.MAC[i] = byte(addr)
		addr >>= 8
	}
	sigStrength, _ := args.GetRawSignalStrengthInDBm()
	result := ScanResult{
		RSSI:    sigStrength,
		Address: adr,
	}

	var manufacturerData map[uint16][]byte = make(map[uint16][]byte)
	if winAdv, err := args.GetAdvertisement(); err == nil && winAdv != nil {
		vector, _ := winAdv.GetManufacturerData()
		size, _ := vector.GetSize()
		for i := uint32(0); i < size; i++ {
			element, _ := vector.GetAt(i)
			manData := (*advertisement.BluetoothLEManufacturerData)(element)
			companyID, _ := manData.GetCompanyId()
			buffer, _ := manData.GetData()
			manufacturerData[companyID] = bufferToSlice(buffer)
		}
	}

	// Note: the IsRandom bit is never set.
	advertisement, _ := args.GetAdvertisement()
	localName, _ := advertisement.GetLocalName()
	result.AdvertisementPayload = &advertisementFields{
		AdvertisementFields{
			LocalName:        localName,
			ManufacturerData: manufacturerData,
		},
	}

	return result
}

func bufferToSlice(buffer *streams.IBuffer) []byte {
	dataReader, _ := streams.FromBuffer(buffer)
	defer dataReader.Release()
	bufferSize, _ := buffer.GetLength()
	if bufferSize == 0 {
		return nil
	}
	data, _ := dataReader.ReadBytes(bufferSize)
	return data
}

// StopScan stops any in-progress scan. It can be called from within a Scan
// callback to stop the current scan. If no scan is in progress, an error will
// be returned.
func (a *Adapter) StopScan() error {
	if a.watcher == nil {
		return errNotScanning
	}
	return a.watcher.Stop()
}

// Device is a connection to a remote peripheral.
type Device struct {
	device         *bluetooth.BluetoothLEDevice
	session        *genericattributeprofile.GattSession
	pairingHandler *foundation.TypedEventHandler
}

func createDevice(bleDevice *bluetooth.BluetoothLEDevice, session *genericattributeprofile.GattSession) *Device {

	device := &Device{bleDevice, session, nil}
	device.attemptAutoPairing()
	return device
}

func (d *Device) attemptAutoPairing() bool {

	if d.pairingHandler == nil {
		// Check if pairing is supported by the device
		deviceInfo, err := d.device.GetDeviceInformation()
		if err != nil {
			return false
		}
		pairingInfo, err := deviceInfo.GetPairing()
		if err != nil {
			return false
		}
		canPair, err := pairingInfo.GetCanPair()
		if err != nil {
			return false
		}
		if canPair {

			// Attempt to pair with the device automatically
			customPairing, err := pairingInfo.GetCustom()
			if err != nil {
				return false
			}

			// we store the handler as we need to release it when this device
			// is no longer in use
			d.pairingHandler, err = setupAutoAcceptPairing(customPairing)
			if err != nil {
				return false
			}

			// Now initiate a simple confirmation-only pairing
			// Note: Should we attempt other types if this fails?
			// This should be done by the OS but WinRT only does it when pairing
			// through the windows settings app
			pairingOp, err := customPairing.PairAsync(enumeration.DevicePairingKindsConfirmOnly)
			if err != nil {
				return false
			}

			// Wait for the operation to complete
			if err := awaitAsyncOperation(pairingOp, enumeration.SignatureDevicePairingResult); err != nil {
				return false
			}

			// Check the status to see if we succeeded
			res, err := pairingOp.GetResults()
			if err != nil {
				return false
			}
			status, err := (*enumeration.DevicePairingResult)(res).GetStatus()
			if err != nil {
				return false
			}
			switch status {
			case enumeration.DevicePairingResultStatusPaired:
				return true
			case enumeration.DevicePairingResultStatusAlreadyPaired:
				return true
			default:
				return false
			}
		}
	}

	return false
}

func setupAutoAcceptPairing(customPairing *enumeration.DeviceInformationCustomPairing) (*foundation.TypedEventHandler, error) {

	// Setup pairing request handler to autocomplete the
	// pairing process

	// TypedEventHandler<DeviceInformationCustomPairing, DevicePairingRequestedEventArgs>
	pairingRequestedGuid := winrt.ParameterizedInstanceGUID(
		foundation.GUIDTypedEventHandler,
		enumeration.SignatureDeviceInformationCustomPairing,
		enumeration.SignatureDevicePairingRequestedEventArgs,
	)
	pairingRequestedHandler := foundation.NewTypedEventHandler(ole.NewGUID(pairingRequestedGuid), func(instance *foundation.TypedEventHandler, sender, args unsafe.Pointer) {
		if args != nil {
			requestedEventArgs := (*enumeration.DevicePairingRequestedEventArgs)(args)
			requestedEventArgs.Accept()
		}
	})

	// Add the handler to the PairingRequested event
	_, err := customPairing.AddPairingRequested(pairingRequestedHandler)
	if err != nil {
		return nil, err
	}

	// return the handler to be freed when no longer needed
	return pairingRequestedHandler, nil
}

// Connect starts a connection attempt to the given peripheral device address.
//
// On Linux and Windows, the IsRandom part of the address is ignored.
func (a *Adapter) Connect(address Address, params ConnectionParams) (*Device, error) {
	var winAddr uint64
	for i := range address.MAC {
		winAddr += uint64(address.MAC[i]) << (8 * i)
	}

	// IAsyncOperation<BluetoothLEDevice>
	bleDeviceOp, err := bluetooth.FromBluetoothAddressAsync(winAddr)
	if err != nil {
		return nil, err
	}

	// We need to pass the signature of the parameter returned by the async operation:
	// IAsyncOperation<BluetoothLEDevice>
	if err := awaitAsyncOperation(bleDeviceOp, bluetooth.SignatureBluetoothLEDevice); err != nil {
		return nil, fmt.Errorf("error connecting to device: %w", err)
	}

	res, err := bleDeviceOp.GetResults()
	if err != nil {
		return nil, err
	}

	// The returned BluetoothLEDevice is set to null if FromBluetoothAddressAsync can't find the device identified by bluetoothAddress
	if uintptr(res) == 0x0 {
		return nil, fmt.Errorf("device with the given address was not found")
	}

	bleDevice := (*bluetooth.BluetoothLEDevice)(res)

	// Creating a BluetoothLEDevice object by calling this method alone doesn't (necessarily) initiate a connection.
	// To initiate a connection, we need to set GattSession.MaintainConnection to true.
	dID, err := bleDevice.GetBluetoothDeviceId()
	if err != nil {
		return nil, err
	}

	// Windows does not support explicitly connecting to a device.
	// Instead it has the concept of a GATT session that is owned
	// by the calling program.
	gattSessionOp, err := genericattributeprofile.FromDeviceIdAsync(dID) // IAsyncOperation<GattSession>
	if err != nil {
		return nil, err
	}

	if err := awaitAsyncOperation(gattSessionOp, genericattributeprofile.SignatureGattSession); err != nil {
		return nil, fmt.Errorf("error getting gatt session: %w", err)
	}

	gattRes, err := gattSessionOp.GetResults()
	if err != nil {
		return nil, err
	}
	newSession := (*genericattributeprofile.GattSession)(gattRes)
	// This keeps the device connected until we set maintain_connection = False.
	if err := newSession.SetMaintainConnection(true); err != nil {
		return nil, err
	}

	return createDevice(bleDevice, newSession), nil
}

// Disconnect from the BLE device. This method is non-blocking and does not
// wait until the connection is fully gone.
func (d *Device) Disconnect() error {
	defer d.device.Release()
	defer d.session.Release()

	if d.pairingHandler != nil {
		defer d.pairingHandler.Release()
	}
	if err := d.session.Close(); err != nil {
		return err
	}
	if err := d.device.Close(); err != nil {
		return err
	}

	return nil
}
