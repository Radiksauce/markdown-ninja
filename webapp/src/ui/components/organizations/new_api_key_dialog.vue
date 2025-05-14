<template>
  <sl-dialog :open="model" @sl-request-close="close(true)" :label="dialogTitle">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>


    <div v-if="apiKey" class="flex flex-col">
      <sl-input :value="token" @input="token = $event.target.value"
        label="Your API Key" readonly />
    </div>
    <div v-else class="flex-1">
      <sl-input :value="name" @input="name = $event.target.value"
        label="Name" placeholder="Give a name to your API key" />
    </div>

    <div slot="footer" class="mt-5 flex flex-row space-x-3 place-content-end">
      <div v-if="apiKey">
        <sl-button outline @click="close(true)">
          Close
        </sl-button>
      </div>
      <div v-else class="space-x-3">
        <sl-button outline @click="close(true)">
          Cancel
        </sl-button>
        <sl-button variant="primary" :loading="loading" @click="createApiKey">
          Create
        </sl-button>
      </div>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType, type Ref, watch, computed } from 'vue'
import type { ApiKey, CreateApiKeyInput } from '@/api/model';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { useMdninja } from '@/api/mdninja';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';

// props
const model = defineModel({
  type: Boolean as PropType<boolean>,
  required: true,
});

const props = defineProps({
  organizationId: {
    type: String as PropType<string>,
    required: true,
  },
});

// events
const $emit = defineEmits(['created', 'update:modelValue']);

// composables
const $mdninja = useMdninja();

// lifecycle

// variables
let loading = ref(false);
let error = ref('');
let token = ref('');
let name = ref('');
let apiKey: Ref<ApiKey | null> = ref(null);

// computed
const dialogTitle = computed(() => {
  return apiKey ? 'Your new API key' : 'Create a new API key';
})

// watch
watch(() => model.value, () => resetValues());

// functions
function resetValues() {
  token.value = '';
  name.value = '';
  apiKey.value = null;
}

function close(force: boolean) {
  if (!force && apiKey.value) {
    return;
  }

  if (apiKey.value) {
    $emit('created', apiKey.value);
  }
  model.value = false;
}

async function createApiKey() {
  loading.value = true;
  error.value = '';
  const input: CreateApiKeyInput = {
    organization_id: props.organizationId,
    name: name.value,
  }

  try {
    const newApiKey = await $mdninja.createApiKey(input);
    token.value = newApiKey.token!;
    apiKey.value = newApiKey;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
