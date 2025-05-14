<template>
  <div class="w-full">
    <div class="rounded-md bg-red-50 p-4" v-if="error">
      <div class="flex">
        <div class="ml-3">
          <p class="text-sm text-red-700">
            {{ error }}
          </p>
        </div>
      </div>
    </div>

    <div v-if="website" class="w-full flex flex-col">
      <PageEditor v-model="page" :tags="tags" :website="website" :type="pageType" />
    </div>

  </div>
</template>

<script lang="ts" setup>
import { onBeforeMount, ref, type Ref } from 'vue'
import PageEditor from '@/ui/components/websites/page_editor.vue';
import { PageType, type Page, type GetWebsiteInput, type Website, type GetTagsInput, type Tag } from '@/api/model';
import { useRoute } from 'vue-router';
import { useMdninja } from '@/api/mdninja';

// props

// events
onBeforeMount(() => fetchData());

// composables
const $mdninja = useMdninja();
const $route = useRoute();

// lifecycle

// variables
const websiteId = $route.params.website_id as string;
const pageId = $route.params.page_id as string;
const pageType = PageType.Page;

let loading = ref(false);
let error = ref('');
let website: Ref<Website | null> = ref(null);
let page: Ref<Page | null> = ref(null);
let tags: Ref<Tag[]> = ref([]);

// computed

// watch

// functions
async function fetchData() {
  loading.value = true;
  error.value = '';
  const getWebsiteInput: GetWebsiteInput = {
    id: websiteId,
  };
  const getTagsInput: GetTagsInput = {
    website_id: websiteId,
  };

  try {
    const [pageRes, websiteRes, tagsRes] = await Promise.all([
      $mdninja.fetchPage(pageId),
      $mdninja.getWebsite(getWebsiteInput),
      $mdninja.fetchTags(getTagsInput),
    ]);
    tags.value = tagsRes;
    page.value = pageRes;
    website.value = websiteRes;
  } catch (err: any) {
    error.value = err.message;
  } finally {
    loading.value = false;
  }
}
</script>
