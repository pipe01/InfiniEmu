<template lang="pug">
div
    div.position-relative
        canvas(:width="width" :height="height" ref="canvas"
            @contextmenu.prevent="" @mousedown="onMouseDown" @mouseup="onMouseUp" @mousemove="onMouseMove"
            :style="{ width: `${width + sizeOffset}px`, height: `${height + sizeOffset}px` }")

        .sleep-cover(v-if="off" :style="{ width: `${width + sizeOffset}px`, height: `${height + sizeOffset}px` }")
            span Screen is off

    .resize-handle.mt-2.mb-3(@mousedown="onResizeHandleMouseDown")
</template>

<script lang="ts">
export enum Direction {
    Left = 0x03,
    Right = 0x04,
    Up = 0x01,
    Down = 0x02
}
</script>

<script lang="ts" setup>
import { onMounted, ref } from "vue";

const props = defineProps<{
    width: number;
    height: number;
    off: boolean;
}>();

const emit = defineEmits<{
    (e: "gotCanvas", canvas: HTMLCanvasElement): void
    (e: "buttonDown", isDown: boolean): void
    (e: "startSwipe", direction: Direction, x: number, y: number): void
    (e: "endSwipe"): void
    (e: "startTouch", x: number, y: number): void
    (e: "endTouch"): void
    (e: "resized", width: number, height: number): void
}>();

const canvas = ref<HTMLCanvasElement | null>(null);

onMounted(() => {
    emit("gotCanvas", canvas.value!);
});

let isMouseDown = false, isButtonDown = false;
let hasSwiped = false;
let mouseDownX = 0, mouseDownY = 0;

const sizeOffset = ref(0);

const minSwipeDistancePixels = 50;

const normalizePos = (pos: number) => (pos / (props.width + sizeOffset.value)) * props.width;

function onMouseDown(e: MouseEvent) {
    e.preventDefault();

    if (e.button == 0) {
        isMouseDown = true;

        mouseDownX = normalizePos(e.offsetX);
        mouseDownY = normalizePos(e.offsetY);
    } else if (e.button == 2) {
        isButtonDown = true;

        emit("buttonDown", true);
    }
}

function onMouseMove(e: MouseEvent) {
    if (!isMouseDown) {
        return;
    }

    e.preventDefault();

    const x = normalizePos(e.offsetX);
    const y = normalizePos(e.offsetY);
    
    const distX = x - mouseDownX;
    const distY = y - mouseDownY;
    const dist = Math.sqrt(distX * distX + distY * distY);

    if (dist > minSwipeDistancePixels && !hasSwiped) {
        hasSwiped = true;

        let dir: Direction;

        if (Math.abs(distX) > Math.abs(distY)) {
            dir = distX > 0 ? Direction.Right : Direction.Left;
        } else {
            dir = distY > 0 ? Direction.Up : Direction.Down;
        }

        emit("startSwipe", dir, x, y);
    }
}

function onMouseUp(e: MouseEvent) {
    e.preventDefault();

    if (isButtonDown) {
        isButtonDown = false;

        emit("buttonDown", false)
    }

    if (isMouseDown) {
        isMouseDown = false;

        if (hasSwiped) {
            hasSwiped = false;
            emit("endSwipe");
        } else {
            emit("startTouch", normalizePos(e.offsetX), normalizePos(e.offsetY));
            setTimeout(() => emit("endTouch"), 200);
        }
    }
}

let resizePrevY = 0;

function onResizeHandleMouseDown(e: MouseEvent) {
    e.preventDefault();

    document.addEventListener("mousemove", onResizeHandleMouseMove);
    document.addEventListener("mouseup", onResizeHandleMouseUp);
    resizePrevY = e.clientY;
}

function onResizeHandleMouseMove(e: MouseEvent) {
    e.preventDefault();

    sizeOffset.value += e.clientY - resizePrevY;
    resizePrevY = e.clientY;

    emit("resized", props.width + sizeOffset.value, props.height + sizeOffset.value);
}

function onResizeHandleMouseUp(e: MouseEvent) {
    e.preventDefault();

    document.removeEventListener("mousemove", onResizeHandleMouseMove);
    document.removeEventListener("mouseup", onResizeHandleMouseUp);
}
</script>

<style lang="scss" scoped>
canvas {
    background-color: black;
}

.sleep-cover {
    position: absolute;
    top: 0;
    left: 0;
    bottom: 0;
    right: 0;
    background-color: black;
    pointer-events: none;

    & > span {
        position: absolute;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        color: white;
        opacity: 0.3;
    }
}

.resize-handle {
    cursor: ns-resize;
    height: 10px;

    border-top: 1px solid currentColor;
    border-bottom: 1px solid currentColor;
    opacity: 0.25;
}
</style>
