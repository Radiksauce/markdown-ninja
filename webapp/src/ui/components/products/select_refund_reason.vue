<template>
  <sl-select :value="selected" @sl-change="selected = $event.target.value" label="Refund reason">
    <sl-option v-for="refundReason in refundReasons" :value="refundReason">
      {{ refundReason }}
    </sl-option>
  </sl-select>
</template>

<script lang="ts" setup>
import { RefundReason } from '@/api/model';
import { computed, type PropType } from 'vue';
import SlSelect from '@shoelace-style/shoelace/dist/components/select/select.js';
import SlOption from '@shoelace-style/shoelace/dist/components/option/option.js';

// props
const props = defineProps({
  modelValue: {
    type: String as PropType<RefundReason | undefined>,
    required: false,
  },
});


// events
const $emit = defineEmits(['update:modelValue']);

// composables

// lifecycle

// variables
const refundReasons = [
  RefundReason.RequestedByCustomer,
  RefundReason.Fraudulent,
  RefundReason.Duplicate,
];

// computed
const selected = computed({
  get(): RefundReason | undefined {
    return props.modelValue;
  },
  set(value: RefundReason | undefined) {
    $emit('update:modelValue', value);
  }
});

// watch

// functions
</script>
