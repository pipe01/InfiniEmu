export type FileInfo = {
    name: string;
    fullPath: string;
    size: number;
    type: "file" | "dir";
};

export type MessageToWorkerType =
    { type: "setCanvas", data: OffscreenCanvas } |
    { type: "start", data: void } |
    { type: "stop", data: void } |
    { type: "doTouch", data: { gesture: number, x: number, y: number } } |
    { type: "clearTouch", data: void } |
    { type: "pressButton", data: void } |
    { type: "releaseButton", data: void } |
    { type: "setProgram", data: ArrayBuffer } |
    { type: "readDir", data: string } |
    { type: "readFile", data: string };

export type MessageFromWorkerType =
    { type: "ready", data: void } |
    { type: "error", data: { message: string | undefined, stack: string | undefined, string: string | undefined } } |
    { type: "dirFiles", data: FileInfo[] } |
    { type: "fileData", data: { path: string, data: ArrayBuffer } } |
    { type: "running", data: boolean } |
    { type: "rttFound", data: void } |
    { type: "rttData", data: string } |
    { type: "lcdSleeping", data: boolean } |
    { type: "cpuSleeping", data: boolean } |
    { type: "performance", data: { loopTime: number, ips: number, totalSRAM: number } };
