<template>
  <sl-dialog :open="model" @sl-request-close="model = false" label="Add Custom Domain">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <sl-input label="Domain" :value="hostname" @input="hostname = $event.target.value.trim().toLowerCase()" type="text"
      :disabled="loading" placeholder="mywebsite.com" />

    <div slot="footer" class="mt-5 flex flex-row space-x-3 place-content-end">
      <sl-button outline @click="close()">
        Close
      </sl-button>
      <sl-button variant="primary" :loading="loading" @click="addDomain()">
        Add Domain
      </sl-button>
    </div>
  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType } from 'vue'
import type { AddDomainInput } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';

// props
const model = defineModel({
  type: Boolean as PropType<boolean>,
  required: true,
});

const props = defineProps({
  websiteId: {
    type: String as PropType<string>,
    required: true,
  },
});

// events
const $emit = defineEmits(['created']);

// composables
const $mdninja = useMdninja();

// lifecycle

// variables
let loading = ref(false);
let error = ref('');
let hostname = ref('');

// computed

// watch

// functions
function close() {
  model.value = false;
  resetValues();
}

function resetValues() {
  hostname.value = '';
  error.value = '';
  loading.value = false;
}

async function addDomain() {
  loading.value = true;
  error.value = '';
  const input: AddDomainInput = {
    website_id: props.websiteId,
    hostname: hostname.value.trim(),
    primary: false,
  }

  try {
    const newDomain = await $mdninja.addDomain(input);
    $emit('created', newDomain);
    close();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
