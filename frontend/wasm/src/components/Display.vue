<template lang="pug">
canvas(:width="width" :height="height" ref="canvas")
</template>

<script lang="ts" setup>
import { onMounted, ref } from "vue";

defineProps<{
    width: number;
    height: number;
}>();

const emit = defineEmits<{
    (e: "gotCanvas", canvas: HTMLCanvasElement): void
}>();

const canvas = ref<HTMLCanvasElement | null>(null);

onMounted(() => {
    emit("gotCanvas", canvas.value!);
});
</script>

<style scoped>
canvas {
    background-color: black;
}
</style>