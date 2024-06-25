export type LFSFile = {
    name: string;
    size: number;
};

export type MessageToWorkerType =
    { type: "loadProgram", data: string } |
    { type: "setCanvas", data: OffscreenCanvas } |
    { type: "start", data: void } |
    { type: "stop", data: void } |
    { type: "doTouch", data: { gesture: number, x: number, y: number } } |
    { type: "clearTouch", data: void } |
    { type: "pressButton", data: void } |
    { type: "releaseButton", data: void } |
    { type: "setProgram", data: ArrayBuffer } |
    { type: "readDir", data: void };

export type MessageFromWorkerType =
    { type: "ready", data: void } |
    { type: "error", data: { message: string | undefined, stack: string | undefined, string: string | undefined } } |
    { type: "dirFiles", data: LFSFile[] } |
    { type: "running", data: boolean } |
    { type: "rttFound", data: void } |
    { type: "rttData", data: string } |
    { type: "lcdSleeping", data: boolean } |
    { type: "cpuSleeping", data: boolean } |
    { type: "performance", data: { loopTime: number, ips: number, totalSRAM: number } };
