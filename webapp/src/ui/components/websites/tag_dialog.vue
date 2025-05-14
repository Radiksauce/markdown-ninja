<template>
  <sl-dialog :open="model" @sl-request-close="model = false" :label="dialogLabel">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <sl-input :value="name" @input="name = slugifyTagName($event.target.value)"
      :disabled="loading" placeholder="my-tag" label="Name"
    />

    <div class="flex mt-6">
      <sl-textarea label="Description" :value="description" @input="description = $event.target.value"
        rows="8" :disabled="loading"
      />
    </div>


    <div slot="footer" class="mt-5 flex flex-row space-x-3 place-content-end">
      <sl-button outline @click="close()">
        Cancel
      </sl-button>
      <sl-button v-if="tag" variant="primary" @click="updateTag()" :loading="loading">
        Save
      </sl-button>
      <sl-button v-else variant="primary" @click="createTag()" :loading="loading">
        Create
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType, watch, computed } from 'vue';
import type { CreateTagInput, Tag, UpdateTagInput } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';
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
  tag: {
    type: Object as PropType<Tag | null>,
    required: false,
    default: null,
  },
});

// events
const $emit = defineEmits(['created', 'updated']);

// composables
const $mdninja = useMdninja();

// lifecycle

// variables
let name = ref('');
let renderInEmails = ref(false);
let description = ref('');
let error = ref('');
let loading = ref(false);

// computed
const dialogLabel = computed(() => {
  return props.tag ? 'Edit Tag' : 'New Tag';
});

// watch
watch(() => props.tag, () => resetValues());

// functions
function close() {
  model.value = false;
  resetValues();
}

function slugifyTagName(name: string): string {
  name = name.toLowerCase();
  name = name.replaceAll(' ', '-');
  name = name.replaceAll('.', '-');
  name = name.replaceAll('_', '-');
  name = name.replaceAll('--', '-');
  return name.trim();
}

function resetValues() {
  if (props.tag) {
    name.value = props.tag.name;
    description.value = props.tag.description;
  } else {
    name.value = '';
    renderInEmails.value = false;
    description.value = '';
  }
  error.value = '';
}

async function createTag() {
  loading.value = true;
  error.value = '';
  const input: CreateTagInput = {
    website_id: props.websiteId,
    name: name.value,
    description: description.value,
  };

  try {
    const newTag = await $mdninja.createTag(input);
    $emit('created', newTag);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function updateTag() {
  loading.value = true;
  error.value = '';
  const input: UpdateTagInput = {
    id: props.tag!.id,
    name: name.value,
    description: description.value,
  };

  try {
    const tag = await $mdninja.updateTag(input);
    $emit('updated', tag);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
