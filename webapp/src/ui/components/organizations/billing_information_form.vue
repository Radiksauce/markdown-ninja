<template>
  <div class="flex flex-col space-y-4">
    <sl-input :value="model.name" @input="model.name = $event.target.value"
      label="Name" :disabled="loading"
    />

    <sl-input :value="model.email" @input="model.email = $event.target.value" type="email"
      label="Email" :disabled="loading"
    />

    <sl-input :value="model.address_line1" @input="model.address_line1 = $event.target.value"
      label="Address Line 1" :disabled="loading"
    />

    <sl-input :value="model.address_line2" @input="model.address_line2 = $event.target.value"
      label="Address Line 2" :disabled="loading"
    />

    <div class="flex flex-row space-x-4">
      <sl-input :value="model.city" @input="model.city = $event.target.value"
        label="  Postal Code" :disabled="loading"
      />

      <sl-input :value="model.postal_code" @input="model.postal_code = $event.target.value"
        label="City" :disabled="loading"
      />
    </div>

    <sl-input :value="model.state" @input="model.state = $event.target.value"
      label="State, Province or Region (optional)" :disabled="loading"
    />

    <div class="flex">
      <SelectCountry v-model="model.country_code" />
    </div>


    <sl-input :value="model.tax_id" @input="model.tax_id = $event.target.value"
      label="VAT Number (optional)" :disabled="loading" placeholder="VAT Identification Number"
    />
  </div>
</template>

<script lang="ts" setup>
import type { BillingInformation } from '@/api/model';
import { onBeforeMount, type ModelRef, type PropType } from 'vue';
import { useStore } from '@/app/store';
import SelectCountry from '@/ui/components/kernel/select_country.vue';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

// props
defineProps({
  loading: {
    type: Boolean as PropType<boolean>,
    required: false,
    default: false,
  }
});

const model: ModelRef<BillingInformation> = defineModel({ required: true });

onBeforeMount(() => {
  if (model.value.country_code === '') {
    model.value.country_code = $store.country;
  }
})

// events

// composables
const $store = useStore();

// lifecycle

// variables

// computed

// watch

// functions
</script>
