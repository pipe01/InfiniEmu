package emulator

const BaseFrequencyHZ = 18_000_000

const (
	PinCharging           = 12
	PinCst816sReset       = 10
	PinButton             = 13
	PinButtonEnable       = 15
	PinCst816sIrq         = 28
	PinPowerPresent       = 19
	PinBma421Irq          = 8
	PinMotor              = 16
	PinLcdBacklightLow    = 14
	PinLcdBacklightMedium = 22
	PinLcdBacklightHigh   = 23
	PinSpiSck             = 2
	PinSpiMosi            = 3
	PinSpiMiso            = 4
	PinSpiFlashCsn        = 5
	PinSpiLcdCsn          = 25
	PinLcdDataCommand     = 18
	PinLcdReset           = 26
	PinTwiScl             = 7
	PinTwiSda             = 6
)
