<template>
  <!-- <div v-html="page.body" /> -->
  <Phtml :html="page.body" />
</template>

<script lang="ts" setup>
import type { Page } from '@/app/model';
import type { PropType } from 'vue';
import Phtml from '@/ui/components/p_html.vue';

// props
defineProps({
  page: {
    type: Object as PropType<Page>,
    required: true,
  },
});

// events

// composables

// lifecycle

// variables

// computed

// watch

// functions
</script>
