<script setup lang="ts">
import { computed } from 'vue';

import { ICONS } from '../icons';

const props = withDefaults(defineProps<{ name: string; size?: number }>(), { size: 20 });
const paths = computed(() => ICONS[props.name] ?? '');
</script>

<template>
  <svg
    class="lx-icon"
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    stroke-width="1.75"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    focusable="false"
    v-html="paths"
  />
</template>

<style scoped>
.lx-icon {
  flex: none;
  display: block;
}
</style>
