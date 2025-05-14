<template>
  <sl-dialog @sl-request-close="model = false" :open="model" label="Background Job">

    <div class="rounded-md bg-red-50 p-4 mb-3" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex-col" v-if="job">

      <div class="flex my-3">
        <span class="font-bold">ID:</span>&nbsp;
        <span>{{ job.id }}</span>
      </div>

      <div class="flex my-3">
        <span class="font-bold">Type:</span>&nbsp;
        <span>{{ job.type }}</span>
      </div>

      <div class="flex my-3">
        <span class="font-bold">Status:</span>&nbsp;
        <span>{{ job.status }}</span>
      </div>

      <div class="flex my-3">
        <span class="font-bold">Created At:</span>&nbsp;
        <span>{{ job.created_at }}</span>
      </div>

      <div class="flex my-3">
        <span class="font-bold">Updated At:</span>&nbsp;
        <span>{{ job.updated_at }}</span>
      </div>

      <div class="flex my-3">
        <span class="font-bold">Failed Attempts:</span>&nbsp;
        <span>{{ job.failed_attempts }}</span>
      </div>

      <div class="flex my-3">
        <span class="font-bold">Retry Startegy:</span>&nbsp;
        <span>{{ job.retry_strategy }}</span>
      </div>

      <div class="flex my-3">
        <span class="font-bold">Timeout:</span>&nbsp;
        <span>{{ job.timeout }}</span>
      </div>


      <div class="flex flex-col my-3">
        <div class="flex">
          <p class="flex font-bold">Data:</p>
        </div>
        <div class="flex">
          <pre class="flex py-[1px] w-full bg-zinc-100 rounded font-normal overflow-x-scroll text-[14px]"><code>{{ job!.data }}</code></pre>
        </div>
      </div>
    </div>


    <div slot="footer" v-if="job" class="flex mt-5 sm:mt-4 space-x-3 justify-end" >
      <sl-button outline @click="close()">
        Close
      </sl-button>
      <sl-button variant="danger" :loading="loading" @click="deleteJob(job!.id)">
        Delete
      </sl-button>
    </div>

  </sl-dialog>
</template>

<script lang="ts" setup>
import { ref, type PropType } from 'vue';
import type { BackgroundJob } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlDialog from '@shoelace-style/shoelace/dist/components/dialog/dialog.js';

// props
const model = defineModel({
  type: Boolean as PropType<boolean>,
  required: true,
});

defineProps({
  modelValue: {
    type: Boolean as PropType<boolean>,
    required: true,
  },
  job: {
    type: Object as PropType<BackgroundJob | null>,
    required: false,
    default: null,
  },
});

// events
const $emit = defineEmits(['deleted']);

// composables
const $mdninja = useMdninja();

// lifecycle

// variables
let loading = ref(false);
let error = ref('');


// computed

// watch

// functions
function close() {
  model.value = false;
}

async function deleteJob(jobId: string) {
  loading.value = true;
  error.value = '';

  try {
    await $mdninja.deleteBackgroundJob(jobId);
    $emit('deleted', jobId);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
