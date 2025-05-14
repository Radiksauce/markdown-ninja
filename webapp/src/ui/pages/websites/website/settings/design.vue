<template>
  <div class="flex-1">
    <div class="px-4 sm:px-6 md:px-0 mb-4">
      <h1 class="text-3xl font-extrabold text-gray-900">Design</h1>
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

    <div v-if="website" class="flex flex-col">
      <div class="flex">
        <sl-select label="Theme" :value="theme" @sl-change="theme = $event.target.value"
          :disabled="loading" :defaultValue="theme">
          <sl-option v-for="builtInTheme in builtInThemes" :value="builtInTheme">
            {{ builtInTheme }}
          </sl-option>
        </sl-select>
      </div>

      <div class="flex mt-5 w-full flex-row align-items-center space-x-3">
        <sl-color-picker label="Background color" format="hex" no-format-toggle :disabled="loading"
          :value="backgroundColor" @sl-change="backgroundColor = $event.target.value" />
        <label for="background_color" class="block text-md font-medium text-gray-700 content-center">
          Background Color
        </label>
      </div>

      <div class="flex mt-5 w-full flex-row align-items-center space-x-3">
        <sl-color-picker label="Text color" format="hex" no-format-toggle :disabled="loading"
          :value="textColor" @sl-change="textColor = $event.target.value" />
        <label for="text_color" class="block text-md font-medium text-gray-700 content-center">
          Text Color
        </label>
      </div>


      <div class="flex mt-5 w-full flex-row align-items-center space-x-3">
        <sl-color-picker label="Accent color" format="hex" no-format-toggle :disabled="loading"
          :value="accentColor" @sl-change="accentColor = $event.target.value" />
        <label for="accent_color" class="block text-md font-medium text-gray-700 content-center">
          Accent Color
        </label>
      </div>


      <div class="flex mt-5 w-full">
        <sl-input label="Logo URL" :value="logo" @input="logo = $event.target.value"
          :disabled="loading"
        />
      </div>


      <div class="flex flex-row my-5">
        <sl-button variant="primary" @click="updateWebsite()" :loading="loading">
          Save
        </sl-button>
      </div>

      <div class="flex flex-col mt-5">
          <div class="flex flex-col">
            <label for="description" class="block text-md font-medium text-gray-700">
              Website's Icon
            </label>
            <p class="block text-gray-400 font-light text-sm">A square PNG icon. We recommend 1024x1024 px.</p>
          </div>

          <div class="flex my-3">
            <img class="w-10 h-10 rounded-full" :src="iconUrl" alt="Website icon" />
          </div>

          <div class="flex">
            <sl-button variant="primary" @click="onUpdateIconClicked()" :loading="loading">
              Update Icon
            </sl-button>
          </div>
        </div>

    </div>
  </div>

  <input type="file" class="hidden" ref="iconInput" accept=".png" v-on:change="handleIconUpload(true)" />
</template>

<script lang="ts" setup>
import { useMdninja } from '@/api/mdninja';
import { builtInThemes, type GetWebsiteInput, type UpdateWebsiteIconInput, type UpdateWebsiteInput, type Website } from '@/api/model';
import { computed, onBeforeMount, ref, type Ref } from 'vue';
import { useRoute } from 'vue-router';
import SlColorPicker from '@shoelace-style/shoelace/dist/components/color-picker/color-picker.js';
import SlButton from '@shoelace-style/shoelace/dist/components/button/button.js';
import SlSelect from '@shoelace-style/shoelace/dist/components/select/select.js';
import SlOption from '@shoelace-style/shoelace/dist/components/option/option.js';
import SlInput from '@shoelace-style/shoelace/dist/components/input/input.js';

// props

// events

// composables
const $route = useRoute();
const $mdninja = useMdninja();

// lifecycle
onBeforeMount(() => fetchData());

// variables
const websiteId = $route.params.website_id as string;

let website: Ref<Website | null> = ref(null);
let loading = ref(false);
let error = ref('');
let accentColor = ref('');
let textColor = ref('');
let backgroundColor = ref('');
let theme = ref('');
let logo = ref('');
let filesToUpload: File[] = [];
const iconInput = ref(null);

// computed
const iconUrl = computed((): string => {
  if (website.value) {
    return `${$mdninja.generateWebsiteUrl(website.value)}/icon-256.png`;
  }
  return '';
})

// watch

// functions
function resetValues() {
  accentColor.value = website.value!.colors.accent;
  textColor.value = website.value!.colors.text;
  backgroundColor.value = website.value!.colors.background;
  theme.value = website.value!.theme;
  logo.value = website.value!.logo ?? '';
}

async function fetchData() {
  loading.value = true;
  error.value = '';
  const input: GetWebsiteInput = {
    id: websiteId,
  };

  try {
    website.value = await $mdninja.getWebsite(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}

async function updateWebsite() {
  loading.value = true;
  error.value = '';
  const input: UpdateWebsiteInput = {
    id: websiteId,
    accent_color: accentColor.value,
    text_color: textColor.value,
    background_color: backgroundColor.value,
    theme: theme.value,
    logo: logo.value,
  };

  try {
    website.value = await $mdninja.updateWebsite(input);
    resetValues();
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}


function onUpdateIconClicked() {
  ((iconInput.value!) as HTMLElement).click();
}

async function handleIconUpload(direct: boolean) {
  if (direct) {
    filesToUpload = ((iconInput.value!) as HTMLInputElement).files as unknown as File[];
  }

  if (!filesToUpload || filesToUpload.length !== 1) {
    return;
  }

  error.value = '';
  loading.value = true;

  const file = filesToUpload[0];
  if (file.size > 5_000_000) {
    error.value = 'Icon is too large.'
    return
  }

  const updateIconInput: UpdateWebsiteIconInput = {
    website_id: websiteId,
    file: file,
  }

  try {
   await $mdninja.updateWebsiteIcon(updateIconInput);
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
