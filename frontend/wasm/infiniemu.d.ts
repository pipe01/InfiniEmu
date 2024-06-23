declare const tag: unique symbol;

export type Pointer = { readonly [tag]: "Pointer" };
export type Program = { readonly [tag]: "Program" };
export type Pinetime = { readonly [tag]: "Pinetime" };
export type ST7789 = { readonly [tag]: "ST7789" };
export type CST816S = { readonly [tag]: "CST816S" };
export type NRF52832 = { readonly [tag]: "NRF52832" };
export type Pins = { readonly [tag]: "Pins" };
export type Commander = { readonly [tag]: "Commander" };

const module: EmscriptenModuleFactory<EmscriptenModule & {
    ccall(name: string, returnType: string | null, argTypes: string[], args: any[]): any;

    _program_new(size: number): Program;

    _pinetime_new(program: Program, bigRam: boolean): Pinetime;
    _pinetime_get_st7789(pt: Pinetime): ST7789;
    _pinetime_get_cst816s(pt: Pinetime): CST816S;
    _pinetime_get_nrf52832(pt: Pinetime): NRF52832;
    _pinetime_loop(pt: Pinetime, iterations: number): boolean;

    _nrf52832_get_pins(pt: NRF52832): Pins;

    _st7789_is_sleeping(lcd: ST7789): boolean;
    _st7789_read_screen_rgba(lcd: ST7789, buffer: Pointer, rgbaBuffer: Pointer, width: number, height: number): void;

    _commander_new(pt: Pinetime): Commander;
    _commander_set_output(cmd: Commander, output: Pointer): void;

    _commander_output: Pointer;
}>;

export default module;
