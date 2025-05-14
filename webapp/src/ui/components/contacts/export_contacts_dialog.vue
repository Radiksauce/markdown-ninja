<template>
  <sl-dialog :open="model" @sl-request-close="model = false" label="Export Contacts">
    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex-col mt-2">
      <sl-textarea label="Contacts" :value="contacts" @input="contacts = $event.target.value" readonly
        rows="10"
      />
    </div>


    <div slot="footer" class="mt-6 sm:flex sm:flex-row-reverse">
      <sl-button outline @click="close()">
        Close
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType, watch } from 'vue';
import { type ExportContactsInput } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';
import SlTextarea from '@shoelace-style/shoelace/dist/components/textarea/textarea.js';

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
const $emit = defineEmits(['update:modelValue']);

// composables
const $mdninja = useMdninja();

// lifecycle

// variables

let error = ref('');
let loading = ref(false);
let contacts = ref('');

// computed

// watch
watch(() => model.value, (to) => {
  if (to) {
    exoprtContacts();
  }
});

// functions
function close() {
  model.value = false;
  resetValues();
}

function resetValues() {
  contacts.value = '';
}

async function exoprtContacts() {
  loading.value = true;
  error.value = '';
  const input: ExportContactsInput = {
    website_id: props.websiteId,
  };

  try {
    const res = await $mdninja.exportContacts(input);
    contacts.value = res.contacts;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>

