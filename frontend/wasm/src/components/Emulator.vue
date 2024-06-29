<template lang="pug">
template(v-if="!isReady")
    h1 Loading worker...
.row(v-else)
    .col
        .card
            .card-body
                h3.card-title File system

                FileBrowser(:worker="worker" :is-initialized="isStarted" @loadStart="onFileLoadStart" @loadEnd="onFileLoadEnd")
        .card.mt-3(v-if="isStarted")
            .card-body
                h3.card-title Console
                .text-danger(v-if="!foundRTT") Couldn't find Segger RTT block in memory

                Console(:lines="consoleLines" style="height: 400px" @runCommand="sendMessage(worker, 'runCommand', $event)")

    .col(style="flex-grow: 0")
        Display(:width="240" :height="240" :off="isLcdOff" @got-canvas="onGotCanvas"
            @button-down="onButtonDown" @start-swipe="onStartSwipe" @end-swipe="clearTouch"
            @start-touch="onStartTouch" @end-touch="clearTouch")

        .d-flex.flex-column.align-items-stretch.mt-3
            div.text-danger(v-if="isAborted") Emulator aborted
    
            button.btn.btn-success(v-if="!isRunning" @click="start" :disabled="isAborted") Start
            button.btn.btn-danger(v-else @click="stop" :disabled="isAborted") Stop
            button.btn.btn-warning.mt-2(v-if="isStarted" @click="reset" :disabled="isAborted") Reset

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

            .card.mt-3(v-if="isRunning")
                .card-body
                    h3.card-title Controls

                    .d-flex.flex-column.justify-content-center.align-items-center
                        table
                            tr
                                td
                                td
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Up)")
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
                                    button.btn.btn-primary(@click="swipeCenter(Direction.Down)")
                                        i.bi-caret-down-fill
</template>

<script lang="ts" setup>
import { onUnmounted, ref, watch } from "vue";

import MyWorker from "@/worker?worker";

import Display, { Direction } from "@/components/Display.vue";
import Console, { type Line } from "@/components/Console.vue";
import FileBrowser from "@/components/FileBrowser.vue";
import { sendMessage, sendMessageAndWait, useAverage } from "@/utils";
import type { MessageFromWorkerType } from "@/common";

const props = defineProps<{
    programFile: ArrayBuffer,
    autoStart: boolean,
    initResources?: Uint8Array[],
    initTime?: Date,
}>();

const GESTURE_NONE = 0x00;
const GESTURE_SLIDEDOWN = 0x01;
const GESTURE_SLIDEUP = 0x02;
const GESTURE_SLIDELEFT = 0x03;
const GESTURE_SLIDERIGHT = 0x04;
const GESTURE_SINGLETAP = 0x05;
const GESTURE_DOUBLETAP = 0x0B;
const GESTURE_LONGPRESS = 0x0C;

const numberFmt = new Intl.NumberFormat();

const isReady = ref(false);
const isStarted = ref(false);
const isRunning = ref(false);
const isAborted = ref(false);

const turboMode = ref(false);
watch(turboMode, value => sendMessage(worker, "turboMode", value));

const wasRunningBeforeLoad = ref(false);

const isLcdOff = ref(true);
const isCpuSleeping = ref(false);

const foundRTT = ref(false);

const consoleLines = ref<Line[]>([]);

function addConsoleLine(text: string, type: Line["type"]) {
    consoleLines.value.push({ text, type });

    if (consoleLines.value.length > 1000) {
        consoleLines.value.splice(0, consoleLines.value.length - 1000);
    }
}

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

worker.onmessage = async (event) => {
    const { type, data } = event.data as MessageFromWorkerType;

    switch (type) {
        case "error":
            console.error("worker error", data);
            break;

        case "ready":
            await sendMessageAndWait(worker, "setProgram", props.programFile);
            isReady.value = true;

            if (props.initResources) {
                for (const res of props.initResources) {
                    await sendMessageAndWait(worker, "loadArchiveFS", { path: "", zipData: res });
                }
            }
            if (props.initTime) {
                await sendMessageAndWait(worker, "setBackupTime", props.initTime);
            }

            if (props.autoStart)
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
            data.split("\n").forEach(o => addConsoleLine(o, "serial"));
            break;

        case "commandOutput":
            addConsoleLine(data, "command");
            break;

        case "aborted":
            isAborted.value = true;
            isRunning.value = false;
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
            gesture = GESTURE_SLIDELEFT;
            break;
        case Direction.Right:
            gesture = GESTURE_SLIDERIGHT;
            break;
        case Direction.Up:
            gesture = GESTURE_SLIDEUP;
            break;
        case Direction.Down:
            gesture = GESTURE_SLIDEDOWN;
            break;
        default:
            return;
    }

    sendMessage(worker, "doTouch", { gesture, x, y });
}

function clearTouch() {
    sendMessage(worker, "clearTouch", undefined);
}

function onStartTouch(x: number, y: number, isLongPress = false) {
    sendMessage(worker, "doTouch", { gesture: isLongPress ? GESTURE_LONGPRESS : GESTURE_SINGLETAP, x, y });
}

function reset() {
    sendMessage(worker, "reset", undefined);
}
</script>
