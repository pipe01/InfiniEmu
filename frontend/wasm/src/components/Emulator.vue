<template lang="pug">
template(v-if="!isReady")
    h1 Loading worker...
.row(v-else)
    .col
        template(v-if="isStarted")
            .card
                .card-body
                    h3.card-title File system

                    FileBrowser(:worker="worker" :is-initialized="isStarted" @loadStart="onFileLoadStart" @loadEnd="onFileLoadEnd")

            .card.mt-3
                .card-body
                    h3.card-title Console
                    .text-danger(v-if="!foundRTT") Couldn't find Segger RTT block in memory

                    Console(:lines="consoleLines" style="height: 400px")

    .col(style="flex-grow: 0")
        Display(:width="240" :height="240" :off="isLcdOff" @got-canvas="onGotCanvas"
            @button-down="onButtonDown" @start-swipe="onStartSwipe" @end-swipe="clearTouch"
            @start-touch="onStartTouch" @end-touch="clearTouch")
        .d-flex.flex-column.align-items-stretch.mt-3
            button.btn.btn-success(v-if="!isRunning" @click="start") Start
            button.btn.btn-danger(v-else @click="stop") Stop
            button.btn.btn-warning.mt-2(v-if="isStarted" @click="reset") Reset

    .col-3
        template(v-if="isStarted")
            .card
                .card-body
                    h3.card-title Performance
                    .form-check.form-switch
                        input.form-check-input(type="checkbox" v-model="turboMode" id="turboMode")
                        label.form-check-label(for="turboMode") Turbo mode
                    div Instructions per second: {{ numberFmt.format(performance.ips.value.toFixed(0)) }}
                    div Loop time: {{ performance.loopTime.value.toFixed(0) }} ms
                    div CPU: {{ isCpuSleeping ? "Sleeping" : "Running" }}
                    div RAM size: {{ numberFmt.format(performance.sramSize.value) }} bytes

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
</template>

<script lang="ts" setup>
import { onUnmounted, ref, watch } from "vue";

import MyWorker from "@/worker?worker";

import Display, { Direction } from "@/components/Display.vue";
import Console from "@/components/Console.vue";
import FileBrowser from "@/components/FileBrowser.vue";
import { sendMessage, useAverage } from "@/utils";
import type { MessageFromWorkerType } from "@/common";

const props = defineProps<{
    programFile: ArrayBuffer;
}>();

const numberFmt = new Intl.NumberFormat();

const isReady = ref(false);
const isStarted = ref(false);
const isRunning = ref(false);

const turboMode = ref(false);
watch(turboMode, value => sendMessage(worker, "turboMode", value));

const wasRunningBeforeLoad = ref(false);

const isLcdOff = ref(true);
const isCpuSleeping = ref(false);

const foundRTT = ref(false);

const consoleLines = ref<string[]>([]);

const performance = {
    ips: useAverage(1000),
    loopTime: useAverage(1000),
    sramSize: ref(0),
}

const worker = new MyWorker();
onUnmounted(() => worker.terminate());

worker.onerror = (event) => {
    console.error("worker error", event);
};

worker.onmessage = (event) => {
    const { type, data } = event.data as MessageFromWorkerType;

    switch (type) {
        case "error":
            console.error("worker error", data);
            break;

        case "ready":
            sendMessage(worker, "setProgram", props.programFile);
            isReady.value = true;
            start();
            break;

        case "running":
            isRunning.value = data;
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
            performance.sramSize.value = data.totalSRAM;
            break;

        case "rttFound":
            foundRTT.value = true;
            break;

        case "rttData":
            const lines = data.split("\n");
            consoleLines.value.push(...lines);

            if (consoleLines.value.length > 1000) {
                consoleLines.value.splice(0, consoleLines.value.length - 1000);
            }
            break;
    }
};

function onGotCanvas(canvas: HTMLCanvasElement) {
    const offscreen = canvas.transferControlToOffscreen();

    sendMessage(worker, "setCanvas", offscreen, [offscreen]);
}

function start() {
    sendMessage(worker, "start", undefined);
    isStarted.value = true;
}

function stop() {
    sendMessage(worker, "stop", undefined);
}

function onFileLoadStart() {
    wasRunningBeforeLoad.value = isRunning.value;
    stop();
}

function onFileLoadEnd() {
    if (wasRunningBeforeLoad.value)
        start();
}

function onButtonDown(isDown: boolean) {
    if (isDown)
        sendMessage(worker, "pressButton", undefined);
    else
        sendMessage(worker, "releaseButton", undefined);
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

    sendMessage(worker, "doTouch", { gesture, x, y });
}

function clearTouch() {
    sendMessage(worker, "clearTouch", undefined);
}

function onStartTouch(x: number, y: number) {
    sendMessage(worker, "doTouch", { gesture: 0, x, y });
}

function reset() {
    sendMessage(worker, "reset", undefined);
}
</script>
