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

    <div class="flex-1">
      <sl-input :value="name" @input="name = $event.target.value"
        :readonly="loading" :disabled="loading" placeholder="my_snippet" label="Name"
      />
    </div>

    <div class="flex mt-6  flex-col w-full">
      <sl-switch :checked="renderInEmails" @sl-change="renderInEmails = $event.target.checked">
        Render in Emails
      </sl-switch>
    </div>

    <div class="flex mt-6">
      <sl-textarea label="Content" :value="content" @input="content = $event.target.value"
        rows="10" :disabled="loading" placeholder="Write your HTML code here"
      />
    </div>


    <div slot="footer" class="mt-5 flex flex-row space-x-3 place-content-end">
      <sl-button outline @click="close()">
        Cancel
      </sl-button>
      <sl-button variant="primary" v-if="snippet" @click="updateSnippet()" :loading="loading">
        Save
      </sl-button>
      <sl-button v-else variant="primary" @click="createSnippet()" :loading="loading">
        Create
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType, watch, computed } from 'vue';
import type { CreateSnippetInput, Snippet, UpdateSnippetInput } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import SlSwitch from '@shoelace-style/shoelace/dist/components/switch/switch.js';
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
  snippet: {
    type: Object as PropType<Snippet | null>,
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
let content = ref('');
let error = ref('');
let loading = ref(false);

// computed
const dialogLabel = computed(() => {
  return props.snippet ? 'Edit Snippet' : 'New Snippet';
});

// watch
watch(() => props.snippet, () => resetValues());
// watch(() => props.modelValue, () => resetValues());

// functions
function close() {
  model.value = false;
  resetValues();
}

function resetValues() {
  if (props.snippet) {
    name.value = props.snippet.name;
    renderInEmails.value = props.snippet.render_in_emails;
    content.value = props.snippet.content;
  } else {
    name.value = '';
    renderInEmails.value = false;
    content.value = '';
  }
}

async function createSnippet() {
  loading.value = true;
  error.value = '';
  const input: CreateSnippetInput = {
    website_id: props.websiteId,
    name: name.value,
    content: content.value,
    render_in_emails: renderInEmails.value,
  };

  try {
    const newSnippet = await $mdninja.createSnippet(input);
    $emit('created', newSnippet);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function updateSnippet() {
  loading.value = true;
  error.value = '';
  const input: UpdateSnippetInput = {
    id: props.snippet!.id,
    name: name.value,
    content: content.value,
    render_in_emails: renderInEmails.value,
  };

  try {
    const snippet = await $mdninja.updateSnippet(input);
    $emit('updated', snippet);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
