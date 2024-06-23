<template lang="pug">
div.position-relative
    canvas(:width="width" :height="height" ref="canvas"
        @contextmenu.prevent="" @mousedown="onMouseDown" @mouseup="onMouseUp" @mousemove="onMouseMove")

    .sleep-cover(v-if="off" :style="{ width: `${width}px`, height: `${height}px` }")
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

defineProps<{
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
}>();

const canvas = ref<HTMLCanvasElement | null>(null);

onMounted(() => {
    emit("gotCanvas", canvas.value!);
});

let isMouseDown = false, isButtonDown = false;
let hasSwiped = false;
let mouseDownX = 0, mouseDownY = 0;

const minSwipeDistancePixels = 50;

function onMouseDown(e: MouseEvent) {
    e.preventDefault();

    if (e.button == 0) {
        isMouseDown = true;

        mouseDownX = e.offsetX;
        mouseDownY = e.offsetY;
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

    const distX = e.offsetX - mouseDownX;
    const distY = e.offsetY - mouseDownY;
    const dist = Math.sqrt(distX * distX + distY * distY);

    if (dist > minSwipeDistancePixels && !hasSwiped) {
        hasSwiped = true;

        let dir: Direction;

        if (Math.abs(distX) > Math.abs(distY)) {
            dir = distX > 0 ? Direction.Right : Direction.Left;
        } else {
            dir = distY > 0 ? Direction.Up : Direction.Down;
        }

        emit("startSwipe", dir, e.offsetX, e.offsetY);
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
            emit("startTouch", e.offsetX, e.offsetY);
            setTimeout(() => emit("endTouch"), 200);
        }
    }
}
</script>

<style scoped>
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
}
</style>