<template lang="pug">
template(v-if="!isReady")
    h1 Loading worker...
.row(v-else)
    .col
    .col(style="flex-grow: 0")
        Display(:width="240" :height="240" @got-canvas="onGotCanvas"
            @button-down="onButtonDown" @start-swipe="onStartSwipe" @end-swipe="clearTouch"
            @start-touch="onStartTouch" @end-touch="clearTouch")
        div
            button.btn.btn-success(v-if="!isRunning" @click="start") Start
            button.btn.btn-danger(v-else @click="stop") Stop
    .col
        .card(v-if="isStarted")
            .card-body
                h3.card-title Performance
                div Instructions per second: {{ numberFmt.format(performance.ips.value.toFixed(0)) }}
                div Loop time: {{ performance.loopTime.value.toFixed(0) }} ms
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
