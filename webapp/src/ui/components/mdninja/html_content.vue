<template>
  <div ref="component" v-html="html"  class="w-full text-left" />
</template>

<script lang="ts" setup>
import { useLinkify } from '@/libs/linkify';
import { onMounted, ref, type PropType, type Ref, watch, nextTick } from 'vue';

// props
const props = defineProps({
  html: {
    type: String as PropType<string>,
    required: true,
  }
});

// events

// composables
const $linkify = useLinkify()

// lifecycle
onMounted(() => {
  $linkify.linkify(component.value!);
});

// variables
const component: Ref<HTMLElement | null> = ref(null);

// computed

// watch
watch(() => props.html, () => {
  nextTick(() => {
    $linkify.linkify(component.value!);
  });
});
</script>

<style scoped>
a {
  text-decoration: underline;
}
</style>
