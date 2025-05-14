<template>
  <div>
    <span v-if="status === OrderStatus.Completed" class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
      Completed
    </span>
    <span v-else-if="status === OrderStatus.Pending" class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800">
      Pending
    </span>
    <span v-else-if="status === OrderStatus.Canceled" class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-200">
      Canceled
    </span>
    <span v-else class="px-2 inline-flex text-xs leading-5 font-semibold">
      {{ status }}
    </span>
  </div>
</template>

<script lang="ts" setup>
import { OrderStatus } from '@/api/model';
import type { PropType } from 'vue';


// props
defineProps({
  status: {
    type: String as PropType<OrderStatus>,
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
