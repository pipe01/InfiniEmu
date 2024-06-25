<template lang="pug">
.outer(ref="scrollEl")
    .console
        .line(v-for="line in lines") {{ line }}
</template>

<script lang="ts" setup>
import { nextTick, ref, watch } from 'vue';

const props = defineProps<{
    lines: string[];
}>();

const scrollEl = ref<HTMLDivElement | null>(null);

watch(props.lines, () => {
    nextTick(() => scrollEl.value?.scroll(0, scrollEl.value?.scrollHeight ?? 0));
});
</script>

<style lang="scss" scoped>
.outer {
    width: 100%;
    height: 100%;
    overflow-y: auto;
    background-color: black;
}

.console {
    height: 100%;
    width: 100%;
    color: white;
    font-family: 'Courier New', Courier, monospace;
}

.line:hover {
    background-color: rgba(255, 255, 255, 0.1);
}
</style>
