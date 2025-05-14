<template>
  <div class="felx flex-col">
    <div class="flex flex-row justify-between items-center">
      <div class="flex">
        <div class="flex">
          <RouterLink :to="backRoute">
            <sl-button outline>
              Back
            </sl-button>
          </RouterLink>
        </div>

        <div class="flex ml-5">
          <sl-button variant="primary" @click="updateNewsletter" :loading="loading" v-if="modelValue">
            Save
          </sl-button>
          <sl-button variant="primary" @click="createNewsletter" :loading="loading" v-else>
            Create
          </sl-button>
        </div>


      </div>

      <div v-if="modelValue" class="flex">
        <div class="flex">
          <sl-button variant="success" @click="sendNewsletter" :loading="loading">
              Send
          </sl-button>
        </div>
        <div class="flex ml-5">
          <Menu as="div" class="relative inline-block text-left">
            <div>
              <MenuButton class="inline-flex w-full justify-center gap-x-1.5 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-xs ring-1 ring-inset ring-gray-300 hover:bg-gray-50">
                <EllipsisVerticalIcon class="h-5 w-5 text-gray-700" aria-hidden="true" />
              </MenuButton>
            </div>
            <transition enter-active-class="transition ease-out duration-100" enter-from-class="transform opacity-0 scale-95" enter-to-class="transform opacity-100 scale-100" leave-active-class="transition ease-in duration-75" leave-from-class="transform opacity-100 scale-100" leave-to-class="transform opacity-0 scale-95">
              <MenuItems class="absolute right-0 z-10 mt-2 w-56 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-gray-300 focus:outline-none">
                <div class="py-1">
                  <MenuItem v-slot="{ active }">
                    <span @click="sendTestNewsletter"
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Send Test
                    </span>
                  </MenuItem>
                  <MenuItem v-slot="{ active }">
                    <span @click="openDeleteNewsletterDialog"
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Delete Newsletter
                    </span>
                  </MenuItem>
                </div>
              </MenuItems>
            </transition>
          </Menu>
        </div>
      </div>

    </div>

    <div class="rounded-md bg-red-50 p-4 my-5" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div  class="flex flex-col w-full mt-5">
      <sl-input :value="subject" @input="subject = $event.target.value"
          label="Subject" placeholder="Your awesome idea" />
    </div>

    <div class="flex flex-col w-full mt-5" v-if="modelValue">
      <div class="flex">
        <h4 class="text-lg leading-6 font-medium text-gray-900">
          Status
        </h4>
      </div>
      <div class="flex pt-3">
        <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800" v-if="modelValue.sent_at">
          Sent
        </span>
        <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-blue-100 text-blue-800" v-else-if="modelValue.scheduled_for">
          Scheduled
        </span>
        <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-neutral-200" v-else>
          Draft
        </span>
      </div>
    </div>

    <div  class="flex flex-col w-full mt-5">
      <sl-input :value="scheduledFor" @input="scheduledFor = $event.target.value"
          label="Scheduled For" placeholder="2025-01-01T01:01:01Z" />
    </div>

    <div class="flex my-5 flex-col w-full">
      <MarkdownEditor v-model="bodyMarkdown" />
  </div>

  </div>

  <DeleteDialog v-if="modelValue" v-model="showDeleteNewsletterDialog" :error="deleteNewsletterDialogError"
    :title="deleteNewsletterDialogTitle" :message="deleteNewsletterDialogMessage" :loading="deleteNewsletterDialogLoading"
    @delete="deleteNewsletter" />
</template>

<script lang="ts" setup>
import { type CreateNewsletterInput, type Newsletter, type SendNewsletterInput, type UpdateNewsletterInput } from '@/api/model';
import { ref, type PropType, onBeforeMount } from 'vue';
import { useRoute } from 'vue-router';
import DeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import { useRouter } from 'vue-router';
import { useMdninja } from '@/api/mdninja';
import { Menu, MenuButton, MenuItem, MenuItems } from '@headlessui/vue'
import { EllipsisVerticalIcon } from '@heroicons/vue/24/outline'
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import { oneRouteUp } from '@/libs/router_utils';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import { defineAsyncComponent } from 'vue'
const MarkdownEditor = defineAsyncComponent(() =>
  import('@/ui/components/content/markdown_editor.vue')
);
// import MarkdownEditor from '@/ui/components/content/markdown_editor.vue';

// props
const props = defineProps({
  modelValue: {
    type: Object as PropType<Newsletter | null>,
    required: false,
    default: null,
  },
});

// events
const $emit = defineEmits(['update:modelValue']);

// composables
const $route = useRoute();
const $mdninja = useMdninja();
const $router = useRouter();

// lifecycle
onBeforeMount(() => {
  if (props.modelValue) {
    subject.value = props.modelValue.subject;
    scheduledFor.value = props.modelValue.scheduled_for ?? '';
    bodyMarkdown.value = props.modelValue.body_markdown;
  }
});

// variables
const deleteNewsletterDialogTitle = 'Delete Newsletter';
const deleteNewsletterDialogMessage = `Are you sure you want to delete this newsletter? This action cannot be undone.`;
const websiteId = $route.params.website_id as string;
const backRoute = oneRouteUp($route.path);

let loading = ref(false);
let error = ref('');
let subject = ref('');
let scheduledFor = ref('');
let bodyMarkdown = ref('');

let showDeleteNewsletterDialog = ref(false);
let deleteNewsletterDialogError = ref('');
let deleteNewsletterDialogLoading = ref(false);
// computed

// watch

// functions
async function createNewsletter() {
  loading.value = true;
  error.value = '';

  scheduledFor.value = scheduledFor.value.trim();
  const scheduled_for = scheduledFor.value === '' ? undefined : scheduledFor.value;
  const input: CreateNewsletterInput = {
    website_id: websiteId,
    subject: subject.value.trim(),
    scheduled_for: scheduled_for,
    body_markdown: bodyMarkdown.value,
  };

  try {
    const newNewsletter = await $mdninja.createNewsletter(input);
    $router.push(`${backRoute}/${newNewsletter.id}`);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function updateNewsletter() {
  loading.value = true;
  error.value = '';

  scheduledFor.value = scheduledFor.value.trim();
  const scheduled_for = scheduledFor.value === '' ? undefined : scheduledFor.value;
  const input: UpdateNewsletterInput = {
    id: props.modelValue!.id,
    subject: subject.value.trim(),
    scheduled_for: scheduled_for,
    body_markdown: bodyMarkdown.value,
  };

  try {
    const newsletter = await $mdninja.updateNewsletter(input);
    $emit('update:modelValue', newsletter);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

function openDeleteNewsletterDialog() {
  showDeleteNewsletterDialog.value = true;
}

async function deleteNewsletter() {
  deleteNewsletterDialogLoading.value = true;
  deleteNewsletterDialogError.value = '';

  try {
    await $mdninja.deleteNewsletter(props.modelValue!.id);
    showDeleteNewsletterDialog.value = false;
    $router.push(backRoute);
  } catch (err: any) {
    deleteNewsletterDialogError.value = err.message;
  } finally {
    showDeleteNewsletterDialog.value = false;
  }
}

async function sendNewsletter() {
  if (!confirm('Do you really want to send the newsletter now?')) {
    return
  }

  loading.value = true;
  error.value = '';
  const input: SendNewsletterInput = {
    id: props.modelValue!.id!,
  };

  try {
    const newsletter = await $mdninja.sendNewsletter(input);
    $emit('update:modelValue', newsletter);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function sendTestNewsletter() {
  loading.value = true;
  error.value = '';
  const input: SendNewsletterInput = {
    id: props.modelValue!.id!,
    test: true,
  };

  try {
    const newsletter = await $mdninja.sendNewsletter(input);
    $emit('update:modelValue', newsletter);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
