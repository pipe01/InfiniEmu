<template lang="pug">
template(v-if="!isReady")
    h1 Loading worker...
.row(v-else)
    .col
    .col(style="flex-grow: 0")
        Display(:width="240" :height="240" :off="isLcdOff" @got-canvas="onGotCanvas"
            @button-down="onButtonDown" @start-swipe="onStartSwipe" @end-swipe="clearTouch"
            @start-touch="onStartTouch" @end-touch="clearTouch")
        .d-flex.flex-column.align-items-stretch.mt-3
            button.btn.btn-success(v-if="!isRunning" @click="start") Start
            button.btn.btn-danger(v-else @click="stop") Stop
    .col
        template(v-if="isStarted")
            .card
                .card-body
                    h3.card-title Performance
                    div Instructions per second: {{ numberFmt.format(performance.ips.value.toFixed(0)) }}
                    div Loop time: {{ performance.loopTime.value.toFixed(0) }} ms
                    div CPU: {{ isCpuSleeping ? "Sleeping" : "Running" }}

            .card.mt-3
                .card-body
                    h3.card-title Controls

                    .d-flex.flex-column.justify-content-center.align-items-center
                        table
                            tr
                                td
                                td
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Down)")
                                        i.bi-caret-up-fill
                                td
                            tr
                                td
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Left)")
                                        i.bi-caret-left-fill
                                td
                                    button.btn.btn-primary(@mousedown="onButtonDown(true)" @mouseup="onButtonDown(false)")
                                        i.bi-square-fill
                                td
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Right)")
                                        i.bi-caret-right-fill
                            tr
                                td
                                td
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Up)")
                                        i.bi-caret-down-fill
                                td
</template>

<script lang="ts" setup>
import { onUnmounted, ref } from "vue";

import MyWorker from "@/worker?worker";

import Display, { Direction } from "@/components/Display.vue";
import { useAverage } from "@/utils";

const props = defineProps<{
    programFile: ArrayBuffer;
}>();

const numberFmt = new Intl.NumberFormat();

const isReady = ref(false);
const isStarted = ref(false);
const isRunning = ref(false);

const isLcdOff = ref(true);
const isCpuSleeping = ref(false);

const performance = {
    ips: useAverage(1000),
    loopTime: useAverage(1000),
}

const worker = new MyWorker();
onUnmounted(() => worker.terminate());

worker.onmessage = (event) => {
    const { type, data } = event.data;

    switch (type) {
        case "error":
            console.error("worker error", data);
            break;

        case "ready":
            worker.postMessage({ type: "loadProgram", data: props.programFile });
            isReady.value = true;
            break;

        case "lcdSleeping":
            isLcdOff.value = data;
            break;

        case "cpuSleeping":
            isCpuSleeping.value = data;
            break;

        case "performance":
            performance.ips.value = data.ips;
            performance.loopTime.value = data.loopTime;
            break;
    }
};

function onGotCanvas(canvas: HTMLCanvasElement) {
    const offscreen = canvas.transferControlToOffscreen();

    worker.postMessage({ type: "setCanvas", data: offscreen }, [offscreen]);
}

function start() {
    worker.postMessage({ type: "start" });
    isStarted.value = true;
    isRunning.value = true;
}

function stop() {
    worker.postMessage({ type: "stop" });
    isRunning.value = false;
}

function onButtonDown(isDown: boolean) {
    if (isDown)
        worker.postMessage({ type: "pressButton" });
    else
        worker.postMessage({ type: "releaseButton" });
}

const swipeCenter = (direction: Direction) => {
    onStartSwipe(direction, 240 / 2, 240 / 2)
    setTimeout(clearTouch, 100);
};

function onStartSwipe(direction: Direction, x: number, y: number) {
    let gesture: number;
    switch (direction) {
        case Direction.Left:
            gesture = 3;
            break;
        case Direction.Right:
            gesture = 4;
            break;
        case Direction.Up:
            gesture = 1;
            break;
        case Direction.Down:
            gesture = 2;
            break;
        default:
            return;
    }
    
    worker.postMessage({ type: "doTouch", data: { gesture, x, y } });
}

function clearTouch() {
    worker.postMessage({ type: "clearTouch" });
}

function onStartTouch(x: number, y: number) {
    worker.postMessage({ type: "doTouch", data: { gesture: 0, x, y } });
}
</script>
