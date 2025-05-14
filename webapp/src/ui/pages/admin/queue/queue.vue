<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-5">
      <h1 class="text-3xl font-extrabold text-gray-900">Background Jobs</h1>
    </div>

    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div class="flex">
      <JobsList :jobs="jobs" @open="openJobDialog" />
    </div>

  </div>

  <JobDialog :job="selectJob" v-model="showJobDialog" @deleted="onJobDeleted" />
</template>

<script lang="ts" setup>
import type { BackgroundJob } from '@/api/model';
import { useMdninja } from '@/api/mdninja';
import { useStore } from '@/app/store';
import { onBeforeMount, ref, type Ref } from 'vue';
import { useRouter } from 'vue-router';
import JobsList from '@/ui/components/admin/queue_jobs_list.vue';
import JobDialog from '@/ui/components/admin/queue_job_dialog.vue';

// props

// events

// composables
const $store = useStore();
const $mdninja = useMdninja();
const $router = useRouter();

// lifecycle
onBeforeMount(() => {
  if ($store.isAdmin !== true) {
    $router.push('/');
  }
  fetchData();
});

// variables
let loading = ref(false);
let error = ref('');
let jobs = ref([] as BackgroundJob[]);
let selectJob: Ref<BackgroundJob | null> = ref(null);
let showJobDialog = ref(false);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';

  try {
    const res = await $mdninja.listFailedBackgroundJobs();
    jobs.value = res.data;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function openJobDialog(job: BackgroundJob) {
  selectJob.value = job;
  showJobDialog.value = true;
}

function onJobDeleted(jobId: string) {
  jobs.value = jobs.value.filter((job: BackgroundJob) => job.id !== jobId);
  showJobDialog.value = false;
}
</script>
