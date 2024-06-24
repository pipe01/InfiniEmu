<template lang="pug">
.outer
    .console
        .line(v-for="line in lines") {{ line }}

        div(ref="endOfConsole")
</template>

<script lang="ts" setup>
import { nextTick, ref, watch } from 'vue';

const props = defineProps<{
    lines: string[];
}>();

const endOfConsole = ref<HTMLDivElement | null>(null);

watch(props.lines, () => {
    nextTick(() => endOfConsole.value?.scrollIntoView());
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
