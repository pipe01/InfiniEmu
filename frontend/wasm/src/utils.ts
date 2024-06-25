import { customRef, onUnmounted, type Ref } from "vue";
import type { MessageToWorkerType } from "./common";

export function useAverage(interval: number): Ref<number> {
    let sum = 0;
    let count = 0;

    let int: number;

    onUnmounted(() => clearInterval(int));

    return customRef((track, trigger) => {
        let avg = 0;

        int = setInterval(() => {
            avg = sum / count;
            sum = 0;
            count = 0;
            trigger();
        }, interval);

        return {
            get() {
                track();
                return avg;
            },
            set(value) {
                sum += value;
                count++;
            },
        }
    });
}

export function sendMessage<Type extends MessageToWorkerType["type"]>(worker: Worker, type: Type, data: Extract<MessageToWorkerType, { type: Type }>["data"], transfer?: Transferable[]) {
    if (transfer)
        worker.postMessage({ type, data }, transfer);
    else
        worker.postMessage({ type, data });
}

export function downloadURL(url: string, filename: string) {
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
}

export function joinLFSPaths(...paths: string[]) {
    return paths.join("/").replace(/^\//, "").replace(/\/+/g, "/");
}
