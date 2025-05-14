<template>
  <TransitionRoot :show="$store.showSearchbar" as="template" appear>
    <Dialog class="relative z-50" @close="close()">
      <TransitionChild as="template" enter="ease-out duration-300" enter-from="opacity-0" enter-to="opacity-100" leave="ease-in duration-200" leave-from="opacity-100" leave-to="opacity-0">
        <div class="fixed inset-0 bg-gray-500/25 transition-opacity" />
      </TransitionChild>

      <div class="fixed inset-0 z-50 w-screen overflow-y-auto p-4 sm:p-6 md:p-20">
        <TransitionChild as="template" enter="ease-out duration-300" enter-from="opacity-0 scale-95" enter-to="opacity-100 scale-100" leave="ease-in duration-200" leave-from="opacity-100 scale-100" leave-to="opacity-0 scale-95">
          <DialogPanel class="mx-auto max-w-xl transform divide-y divide-gray-100 overflow-hidden rounded-xl bg-[var(--mdninja-background)] shadow-2xl ring-1 ring-gray-200 transition-all">
            <Combobox @update:modelValue="onSelect">
              <div class="grid grid-cols-1">
                <ComboboxInput :value="query" placeholder="Search..." @change="query = $event.target.value"
                  class="border-gray-100 focus:border-gray-100 focus:ring-[transparent] col-start-1 row-start-1 h-12 w-full pl-11 pr-4 text-base text-(--mdninja-text) outline-hidden placeholder:text-gray-400 sm:text-sm" />
                <MagnifyingGlassIcon class="pointer-events-none col-start-1 row-start-1 ml-4 size-5 self-center text-gray-400" aria-hidden="true" />
              </div>

              <ComboboxOptions v-if="filteredPages.length > 0 || filteredTags.length > 0" static
                  class="max-h-96 transform-gpu scroll-py-3 overflow-y-auto p-3 border-none my-0">
                <li v-for="group in searchResults" :key="group.type" class="p-0 m-0">
                  <h2 v-if="group.items.length !== 0"
                    class="bg-gray-100 px-4 py-2 text-sm font-semibold text-gray-900 rounded-md my-1">
                    {{ group.type }}
                  </h2>
                  <ul class="p-0 m-0">
                    <ComboboxOption v-for="item in group.items" :key="item.url" :value="item" as="template" v-slot="{ active }">
                      <li :class="['text-sm font-medium flex cursor-default select-none rounded-md p-2 cursor-pointer', active && 'mdninja-active-search-result outline-hidden']">
                        <!-- <div class="flex-auto"> -->
                          <!-- <p :class="['', active ? 'text-gray-900' : 'text-gray-700']"> -->
                            {{ item.name }}
                          <!-- </p> -->
                        <!-- </div> -->
                      </li>
                    </ComboboxOption>
                  </ul>
                </li>

                <!-- <li v-if="filteredTags.length !== 0">
                  <h2 class="bg-gray-100 -my-2 px-4 py-2.5 text-xs font-semibold text-gray-900 rounded-md mb-2">
                    Tags
                  </h2>
                  <ul class="p-0">
                    <ComboboxOption v-for="item in filteredTags" :key="item.url" :value="item" as="template" v-slot="{ active }">
                      <li :class="['flex cursor-default select-none rounded-md p-3 cursor-pointer', active && 'mdninja-active-search-result outline-hidden']">
                        <div class="flex-auto">
                          <p :class="['text-sm font-medium', active ? 'text-gray-900' : 'text-gray-700']">
                            {{ item.name }}
                          </p>
                          <!- - <p :class="['text-sm', active ? 'text-gray-700' : 'text-gray-500']">
                            {{ item.type }}
                          </p> -- >
                        </div>
                      </li>
                    </ComboboxOption>
                  </ul>
                </li>

                <li v-if="filteredPages.length !== 0">
                  <h2 class="bg-gray-100 -my-2 px-4 py-2.5 text-xs font-semibold text-gray-900 rounded-md mb-2">
                    Pages
                  </h2>
                  <ul class="p-0">
                    <ComboboxOption v-for="item in filteredPages" :key="item.url" :value="item" as="template" v-slot="{ active }">
                      <li :class="['flex cursor-default select-none rounded-md p-3 cursor-pointer', active && 'mdninja-active-search-result outline-hidden']">
                        <div class="flex-auto">
                          <p :class="['text-sm font-medium', active ? 'text-gray-900' : 'text-gray-700']">
                            {{ item.name }}
                          </p>
                          <! -- <p :class="['text-sm', active ? 'text-gray-700' : 'text-gray-500']">
                            {{ item.type }}
                          </p> -- >
                        </div>
                      </li>
                    </ComboboxOption>
                  </ul>
                </li> -->


              </ComboboxOptions>

              <div v-if="query !== '' && filteredTags.length === 0 && filteredPages.length === 0" class="px-6 py-14 text-center text-sm sm:px-14">
                <!-- <ExclamationCircleIcon type="outline" name="exclamation-circle" class="mx-auto size-6 text-gray-400" /> -->
                <p class="mt-4 font-semibold text-gray-900">No results found</p>
              </div>
            </Combobox>
          </DialogPanel>
        </TransitionChild>
      </div>
    </Dialog>
  </TransitionRoot>
</template>

<script lang="ts" setup>
import { computed, ref, watch } from 'vue'
import { MagnifyingGlassIcon } from '@heroicons/vue/20/solid'
import {
  Combobox,
  ComboboxInput,
  ComboboxOptions,
  ComboboxOption,
  Dialog,
  DialogPanel,
  TransitionChild,
  TransitionRoot,
} from '@headlessui/vue'
import { useStore } from '@/app/store'
import { listPages, listTags } from '@/app/mdninja'
import { useRouter } from 'vue-router'

type SearchResult = {
  type: string,
  name: string,
  url: string,
}

// props

// events

// composables
const $store = useStore();
const $router = useRouter();

// lifecycle

// variables
const query = ref('');
const loadingAllPages = ref(false);
const loadingAllTags = ref(false);

// computed
const searchTerms = computed((): string[] => {
  return query.value.toLowerCase()
    .split(' ')
    .filter((term) => term !== '');
});

const searchResults = computed(() => {
  return [
    {
      type: 'Tags',
      items: [...filteredTags.value],
    },
    {
      type: 'Pages',
      items: [...filteredPages.value],
    }
  ]
})

const filteredTags = computed((): SearchResult[] => {
  if (searchTerms.value.length === 0) {
    return [];
  }

  return $store.allTags
    .filter((tag) => includesAll(tag.name.toLowerCase(), searchTerms.value))
    .map((tag) => {
      return {
        type: 'Tag',
        name: `#${tag.name}`,
        url: `/tags/${tag.name}`,
      }
    });
});

const filteredPages = computed((): SearchResult[] => {
  if (searchTerms.value.length === 0) {
    return [];
  }

  return $store.allPages
    .filter((page) => includesAll(page.title.toLowerCase(), searchTerms.value) || includesAll(page.path.toLowerCase(), searchTerms.value))
    .map((page) => {
      return {
        // upperCase the first letter
        type: page.type.charAt(0).toUpperCase() + page.type.slice(1),
        name: page.title,
        url: page.path,
      }
    });
})

// watch
watch(() => $store.showSearchbar, async (to) => {
  if (to) {
    if (loadingAllPages.value === false) {
      loadingAllPages.value = true;
      try {
        await listPages({})
      } finally {
        loadingAllPages.value = false;
      }
    }
    if (loadingAllTags.value === false) {
      loadingAllTags.value = true;
      try {
        await listTags()
      } finally {
        loadingAllTags.value = false;
      }
    }
  }
})

// functions
function close() {
  if ($store.showSearchbar) {
    $store.setShowSearchbar(false);
  }
}

function onSelect(item?: SearchResult) {
  if (item) {
    $router.push(item.url)
    $store.setShowSearchbar(false);
    query.value = '';
  }
}

function includesAll(str: string, searchTerms: string[]): boolean {
  for (let searchTerm of searchTerms) {
    if (!str.includes(searchTerm)) {
      return false;
    }
  }

  return true;
}
</script>

<style scoped>
.mdninja-active-search-result:hover {
  background-color: color-mix(in srgb, var(--mdninja-accent), transparent 93%);
}

li {
  list-style-type: none;
}

/* ul {
  padding: 5px;
} */
</style>
