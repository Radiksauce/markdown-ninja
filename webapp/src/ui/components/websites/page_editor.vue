<template>
  <div class="felx flex-col">
    <div class="flex flex-row justify-between items-center">
      <div class="flex items-center">
        <div class="flex">
          <RouterLink :to="backRoute">
            <sl-button outline>
              Back
            </sl-button>
          </RouterLink>
        </div>
        <div class="flex ml-5">
          <sl-button variant="primary" @click="updatePage" :loading="loading" v-if="modelValue">
              Save
          </sl-button>
          <sl-button variant="primary" @click="createPage" :loading="loading" v-else>
              Create
          </sl-button>
        </div>
      </div>

      <div v-if="modelValue" class="flex items-center">
        <div class="flex">
          <sl-button variant="primary" v-if="draft" @click="publishPage()" :loading="loading">
            Publish
          </sl-button>
          <span v-else class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">
            Published
          </span>
        </div>
        <div v-if="modelValue" class="flex ml-5">
          <Menu as="div" class="relative inline-block text-left">
            <div>
              <MenuButton class="inline-flex w-full justify-center gap-x-1.5 rounded-md bg-white px-3 py-2 text-sm font-semibold text-gray-900 shadow-xs ring-1 ring-gray-300 hover:bg-gray-50">
                <!-- Options -->
                <EllipsisVerticalIcon class="h-5 w-5 text-gray-700" aria-hidden="true" />
              </MenuButton>
            </div>

            <transition enter-active-class="transition ease-out duration-100" enter-from-class="transform opacity-0 scale-95" enter-to-class="transform opacity-100 scale-100" leave-active-class="transition ease-in duration-75" leave-from-class="transform opacity-100 scale-100" leave-to-class="transform opacity-0 scale-95">
              <MenuItems class="absolute right-0 z-10 mt-2 w-56 origin-top-right rounded-md bg-white shadow-lg ring-1 ring-gray-300 focus:outline-none">
                <div class="py-1">
                  <MenuItem v-if="!draft" @click="unpublishPage()" v-slot="{ active }">
                    <span
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Unpublish Page
                    </span>
                  </MenuItem>
                  <MenuItem @click="openDeletePageDialog" v-slot="{ active }">
                    <span
                      :class="[active ? 'bg-neutral-100 text-gray-900' : 'text-gray-700', 'cursor-pointer block px-4 py-2 text-sm']">
                      Delete Page
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

    <div class="flex mt-5 w-full">
      <sl-input label="Title"
        :value="title" @input="title = $event.target.value.trim()" placeholder="Something awesome"
      />
    </div>

    <div class="flex mt-5 w-full">
      <div class="flex flex-col w-full">
        <sl-input label="Url"
          :value="path" @input="path = $event.target.value.trim()"
        />
        <p class="mt-2 text-sm text-gray-500" id="path-description" v-if="website">
           <a :href="pageUrl" target="_blank" rel="noopener" class="hover:underline">{{ pageUrl }}</a>
          </p>
        <p class="mt-2 text-sm text-gray-500 underline" v-if="previewUrl">
          <a :href="previewUrl" target="_blank" rel="noopener">preview</a>
        </p>
      </div>
    </div>

    <div class="flex mt-5 w-full">
      <sl-input label="Tags"
        :value="tagsStr" @input="tagsStr = cleanTagsInput($event.target.value)" placeholder="tag1,tag2,tag3"
      />
    </div>

    <div v-if="type === PageType.Post" class="mt-5 flex flex-col w-full">
      <sl-switch v-if="!modelValue || modelValue.newsletter_sent_at === null"
          :checked="sendAsNewsletter" @sl-change="sendAsNewsletter = $event.target.checked">
        Send as newsletter
      </sl-switch>
      <div v-else class="text-sm text-gray-500 inline align-items-center flex">
        <EnvelopeIcon class="h-6 w-6 text-gray-400 inline align-middle" />
        <span class="ml-2 align-middle">Newsletter sent on {{ date(modelValue!.newsletter_sent_at) }}</span>
      </div>
    </div>

    <!-- <div v-if="type === PageType.Post" class="mt-5 flex flex-col w-full">
      <SwitchGroup
        as="div" class="flex flex-col">
        <span class="grow flex flex-col">
          <SwitchLabel as="span" class="text-sm font-medium text-gray-900" passive>Send as newsletter</SwitchLabel>
        </span>
        <div class="py-1 flex flex-row items-center">
          <div class="flex mr-2">
            <EnvelopeIcon class="h-6 w-6 text-gray-400" />
          </div>
          <div class="flex">
            <Switch v-model="sendAsNewsletter" v-if="!modelValue || modelValue.newsletter_sent_at === null"
              :class="[sendAsNewsletter ? 'bg-(--primary-color)' : 'bg-gray-200', 'relative inline-flex shrink-0 h-6 w-11 border-2 border-transparent rounded-full cursor-pointer transition-colors ease-in-out duration-200']">
              <span aria-hidden="true"
                :class="[sendAsNewsletter ? 'translate-x-5' : 'translate-x-0', 'pointer-events-none inline-block h-5 w-5 rounded-full bg-white shadow transform ring-0 transition ease-in-out duration-200']" />
            </Switch>
            <span v-else class="text-sm text-gray-500 inline align-middle">
              Newsletter sent: {{ date(modelValue!.newsletter_sent_at) }}
            </span>
          </div>
        </div>
      </SwitchGroup>
    </div> -->


    <div class="flex my-6 w-full">
      <MarkdownEditor v-model="bodyMarkdown" :disabled="loading" label="Content" />
    </div>


  </div>

  <DeleteDialog v-if="modelValue" v-model="showDeletePageDialog" :error="deletePageDialogError"
    :title="deletePageDialogTitle" :message="deletePageDialogMessage" :loading="deletePageDialogLoading"
    @delete="deletePage" />
</template>

<script lang="ts" setup>
import { type CreatePageInput, type Page, PageType, type UpdatePageInput, type Website, type Tag, PageStatus } from '@/api/model'
import { ref, type PropType, computed, onBeforeMount } from 'vue'
import DeleteDialog from '@/ui/components/mdninja/delete_dialog.vue';
import { useRoute } from 'vue-router';
import { useRouter } from 'vue-router';
import { useMdninja } from '@/api/mdninja';
import { Menu, MenuButton, MenuItem, MenuItems } from '@headlessui/vue'
import { EllipsisVerticalIcon, EnvelopeIcon } from '@heroicons/vue/24/outline'
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlSwitch from '@shoelace-style/shoelace/dist/components/switch/switch.js';
import { oneRouteUp } from '@/libs/router_utils';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';
import { defineAsyncComponent } from 'vue'
const MarkdownEditor = defineAsyncComponent(() =>
  import('@/ui/components/content/markdown_editor.vue')
);
import date from 'mdninja-js/src/libs/date';

// import MarkdownEditor from '@/ui/components/content/markdown_editor.vue';


// props
const props = defineProps({
  modelValue: {
    type: Object as PropType<Page | null>,
    required: false,
    default: null,
  },
  type: {
    type: String as PropType<PageType>,
    required: true,
  },
  website: {
    type: Object as PropType<Website | null>,
    required: false,
    default: null,
  },
  tags: {
    type: Array as PropType<Tag[]>,
    required: true,
  },
});

// events
const $emit = defineEmits(['update:modelValue']);

// composables
const $mdninja = useMdninja();
const $route = useRoute();
const $router = useRouter();

// lifecycle
onBeforeMount(() => {
  if (props.modelValue) {
    title.value = props.modelValue.title;
    path.value = props.modelValue.path;
    bodyMarkdown.value = props.modelValue.body_markdown;
    draft.value = props.modelValue.status === PageStatus.Draft;
    tagsStr.value = props.modelValue.tags.map((tag) => tag.name).join(', ');
    sendAsNewsletter.value = props.modelValue.send_as_newsletter;
  }
});

// variables
const deletePageDialogTitle = 'Delete Page';
const deletePageDialogMessage = `Are you sure you want to delete this ${props.type}? This action cannot be undone.`;
const websiteId = $route.params.website_id as string;
const backRoute = oneRouteUp($route.path);

let loading = ref(false);
let error = ref('');
let title = ref('');
let path = ref('/');
let draft = ref(true);
let tagsStr = ref('');
let bodyMarkdown = ref('');
let sendAsNewsletter = ref(false);

let showDeletePageDialog = ref(false);
let deletePageDialogError = ref('');
let deletePageDialogLoading = ref(false);

// computed
const previewUrl = computed((): string => {
  if (props.modelValue) {
    return $mdninja.generatePagePreviewUrl(props.website!, props.modelValue);
  }
  return '';
})
const pageUrl = computed((): string => {
  if (props.modelValue) {
    return $mdninja.generatePageUrl(props.website!, props.modelValue);
  }
  return '';
})

// watch

// functions
async function createPage() {
  loading.value = true;
  error.value = '';

  const input: CreatePageInput = {
    website_id: websiteId,
    date: new Date().toISOString(),
    type: props.type,
    title: title.value,
    path: path.value,
    body_markdown: bodyMarkdown.value,
    tags: tagsStrToArray(),
    description: '',
    language: 'en',
    draft: true,
    send_as_newsletter: sendAsNewsletter.value,
  };

  try {
    const page = await $mdninja.createPage(input);
    $router.push(`/websites/${websiteId}/${props.type}s/${page.id}`);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function publishPage(isDraft?: boolean) {
  isDraft ??= false;

  draft.value = isDraft;
  const updated = await updatePage();
  if (!updated) {
    draft.value = !isDraft;
  }
}

function unpublishPage() {
  publishPage(true);
}

// updatePage returns true if the update was successful and false otherwise
async function updatePage(): Promise<boolean> {
  loading.value = true;
  error.value = '';
  let updateSuccessful = true;

  if (sendAsNewsletter.value && !draft.value && !props.modelValue!.newsletter_sent_at) {
    const nowTimestamp = new Date().getTime();
    const dateTimestamp = new Date(props.modelValue!.date).getTime();
    if (dateTimestamp < nowTimestamp) {
      if (!confirm('You are going to send this post as a newsletter. Do you confirm?')) {
        loading.value = false;
        updateSuccessful = false;
        return updateSuccessful;
      }
    }
  }

  const input: UpdatePageInput = {
    id: props.modelValue!.id,
    date: props.modelValue!.date,
    title: title.value,
    path: path.value,
    body_markdown: bodyMarkdown.value,
    tags: tagsStrToArray(),
    // description: props.modelValue!.description,
    language: props.modelValue!.language,
    draft: draft.value,
    send_as_newsletter: sendAsNewsletter.value,
  };

  try {
    const page = await $mdninja.updatePage(input);
    $emit('update:modelValue', page);
  } catch (err: any) {
    error.value = err.message;
    updateSuccessful = false;
  } finally {
    loading.value = false;
  }

  return updateSuccessful;
}

function openDeletePageDialog() {
  showDeletePageDialog.value = true;
}

async function deletePage() {
  deletePageDialogLoading.value = true;
  deletePageDialogError.value = '';

  try {
    await $mdninja.deletePage(props.modelValue!.id);
    showDeletePageDialog.value = false;
    $router.push(backRoute);
  } catch (err: any) {
    deletePageDialogError.value = err.message;
  } finally {
    deletePageDialogLoading.value = false;
  }
}

function cleanTagsInput(tagsStr: string): string {
  tagsStr = tagsStr.trim();
  tagsStr = tagsStr.toLowerCase();
  return tagsStr;
}

function tagsStrToArray() {
  return tagsStr.value.split(',').map((tag) => tag.trim()).filter((tag) => tag.length !== 0);
}
</script>
