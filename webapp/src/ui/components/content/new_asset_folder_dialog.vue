<template>
  <sl-dialog :open="model" @sl-request-close="model = false" label="Create New Folder">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <sl-input :value="name" @input="name = $event.target.value.trim()" required placeholder="The name of your new folder" />

    <div slot="footer" class="mt-5 flex flex-row space-x-3 place-content-end">
      <sl-button outline @click="close(true)">
        Cancel
      </sl-button>
      <sl-button variant="primary" :loading="loading" @click="createFolder()">
        Create
      </sl-button>
    </div>

  </sl-dialog :open="model" @sl-request-close="model = false">
</template>

<script lang="ts" setup>
import { ref, type PropType, watch } from 'vue'
import type { CreateFolderInput } from '@/api/model';
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
  websiteId: {
    type: String as PropType<string>,
    required: true,
  },
  // The parent folder
  folder: {
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
let name = ref('');

// computed

// watch
watch(() => model.value, () => resetValues());

// functions
function resetValues() {
  name.value = '';
}

function close(force: boolean) {
  model.value = false;
}

async function createFolder() {
  loading.value = true;
  error.value = '';

  const input: CreateFolderInput = {
    website_id: props.websiteId,
    folder: props.folder,
    name: name.value,
  };

  try {
    const newFolder = await $mdninja.createAssetFolder(input);
    $emit('created', newFolder)
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
