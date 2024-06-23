import { customRef, onUnmounted, type Ref } from "vue";

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