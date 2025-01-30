// From the perspective of the MCU
export type PinDirection = "i" | "o" | "io";

export function isInput(dir: PinDirection) {
    return dir == "i" || dir == "io";
}

export function isOutput(dir: PinDirection) {
    return dir == "o" || dir == "io";
}

export type Pin = { number: number; name: string; } & (
    { dir: "i"; canChange?: boolean; analog?: false; pull?: "up" | "down" } |
    { dir: "i"; canChange?: boolean; analog: true, intialValue?: number } |
    { dir: "o"; } |
    { dir: "io"; canChange?: boolean; }
);

export const pinetimePins: Pin[] = [
    { number: 2, name: "SpiSck", dir: "o" },
    { number: 3, name: "SpiMosi", dir: "o" },
    { number: 4, name: "SpiMiso", dir: "i" },
    { number: 5, name: "SpiFlashCsn", dir: "o" },
    { number: 6, name: "TwiSda", dir: "io" },
    { number: 7, name: "TwiScl", dir: "io" },
    { number: 8, name: "Bma421Irq", dir: "i" },
    { number: 10, name: "Cst816sReset", dir: "o" },
    { number: 12, name: "Charging", dir: "i", canChange: true, pull: "up" },
    { number: 13, name: "Button", dir: "i", canChange: true },
    { number: 14, name: "LcdBacklightLow", dir: "o" },
    { number: 15, name: "ButtonEnable", dir: "o" },
    { number: 16, name: "Motor", dir: "o" },
    { number: 18, name: "LcdDataCommand", dir: "o" },
    { number: 19, name: "PowerPresent", dir: "i", canChange: true, pull: "up" },
    { number: 22, name: "LcdBacklightMedium", dir: "o" },
    { number: 23, name: "LcdBacklightHigh", dir: "o" },
    { number: 25, name: "SpiLcdCsn", dir: "o" },
    { number: 26, name: "LcdReset", dir: "o" },
    { number: 28, name: "Cst816sIrq", dir: "i" },
    { number: 31, name: "BatteryVoltage", dir: "i", canChange: true, analog: true, intialValue: 3.9 / 2 },
];
