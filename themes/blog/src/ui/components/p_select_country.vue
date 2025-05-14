<template>
  <div>
    <label for="country" class="block text-sm font-medium leading-6">Country</label>
    <select v-model="model" id="country" name="country" :disabled="readonly"
      class="cursor-pointer block w-full rounded-md border-0 pt-1.5 pb-2 pl-3 pr-10 ring-1 ring-inset ring-gray-300 focus:ring-2 focus:ring-[var(--mdninja-accent)] sm:text-sm sm:leading-6">
      <option v-for="country in countries" :value="country.code">
        {{ country.name }}
      </option>
    </select>
  </div>
</template>

<script lang="ts" setup>
import { type PropType } from 'vue';
import countries from '@/data/countries';

// props
defineProps({
  modelValue: {
    type: String as PropType<string>,
    required: false,
  },
  readonly: {
    type: Boolean as PropType<boolean>,
    required: false,
    default: false,
  },
});

const model = defineModel({
  type: String as PropType<string>,
  required: false,
});

// events

// composables

// lifecycle

// variables

// computed

// watch

// functions
</script>
