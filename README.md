# InfiniEmu

InfiniEmu is an emulator that emulates a full [PineTime](https://pine64.org/devices/pinetime/) smartwatch, which includes:

* [NRF52832](https://www.nordicsemi.com/Products/nRF52832) along with its ARM Cortex M4 CPU and peripherals, 
* BMA425 I2C accelerometer
* CST816S I2C touch screen controller
* HRS3300 I2C heart rate sensor
* ST7789 SPI LCD display controller
* A generic SPI flash based on the XT25F32B-S

## Disclaimer

This project isn't production ready by any means, and the emulation almost definitely doesn't completely match a real device.

The goal is to be able to run the same image with the emulator as you would flash on a real device, however InfiniTime 1.14.0 doesn't work on InfiniEmu because of [an issue](https://github.com/InfiniTimeOrg/InfiniTime/pull/2070) that's already fixed but hasn't yet been released on an InfiniTime version. Compiling the latest commit from the InfiniTime repo works fine.

Many things are yet to be implemented, including but not limited to:

* Adjusting battery voltage input
* Sending heartrate data
* Bluetooth

# Usage

There are currently no releases, the easiest way to run InfiniEmu is to download the AppImage artifact from the latest successful [action run](https://github.com/pipe01/InfiniEmu/actions).

To run InfiniEmu, use the following command: `./InfiniEmu-x86_64.AppImage <firmware_path>`, where `<firmware_path>` is the path to the ELF or binary file containing the firmware to run. If an ELF file with symbols is passed, additional information such as FreeRTOS free heap size will be available.

# Building from source

TODO

# Screenshots

![asd](docs/screenshot.jpg)
