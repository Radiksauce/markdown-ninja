<template>
  <div class="flex grow flex-col overflow-y-auto px-6 bg-[var(--mdninja-background)]">
    <div class="flex flex-shrink-0 items-center h-16 justify-between">
      <PLink href="/" @click="$store.toggleSidebar(false)" class="flex hover:no-underline">
        <img class="flex h-8 w-8" :src="$store.website!.logo!" alt="Website logo" />
        <h1 class="flex ml-2.5 sm:ml-3 font-normal text-lg sm:text-xl text-[var(--mdninja-text)]">
          {{ $store.website!.name }}
        </h1>
      </PLink>
    </div>
    <nav class="flex flex-1 flex-col mt-4">
      <ul role="list" class="flex flex-1 flex-col gap-y-7">
        <li>
          <ul role="list" class="-mx-2 space-y-1">
            <li v-for="item in $store.website!.navigation.secondary" :key="item.label">
              <PLink v-if="item.url" :href="item.url" @click="$store.toggleSidebar(false)"
                :class="['rounded-sm text-[var(--mdninja-text)] hover:bg-[var(--mdninja-background)] hover:brightness-[0.95]  group flex gap-x-3 !no-underline p-2 text-sm/6 font-semibold border-l-2 border-transparent',
                  urlMatchRoute(item.url) ? 'bg-[var(--mdninja-background)] brightness-[0.97] text-[var(--mdninja-accent)] border-l-[var(--mdninja-accent)] rounded-l-xs' : '']">
                {{ item.label }}
              </PLink>

              <Disclosure as="div" v-else v-slot="{ open }">
                <DisclosureButton class="shadow-none text-[var(--mdninja-text)] bg-transparent hover:brightness-[0.95] flex w-full items-center gap-x-3 rounded-md p-2 text-left text-sm/6 font-semibold">
                  <!-- <component v-if="item.icon" :is="item.icon" :class="[urlMatchRoute(item.url) ? 'text-(--primary-color)' : 'text-gray-400 group-hover:text-(--primary-color)', 'h-6 w-6 shrink-0']" /> -->
                  {{ item.label }}
                  <ChevronRightIcon :class="[open ? 'rotate-90 text-gray-500' : 'text-gray-400', 'ml-auto size-5 shrink-0']" aria-hidden="true" />
                </DisclosureButton>

                <DisclosurePanel as="ul" class="mt-1 px-2 space-y-1">
                  <li v-for="subItem in item.children" :key="subItem.label">
                    <PLink :href="subItem.url!" @click="$store.toggleSidebar(false)"
                      :class="['py-2 pl-6 pr-2 rounded-sm text-[var(--mdninja-text)] hover:bg-[var(--mdninja-background)] hover:brightness-[0.95]  group flex gap-x-3 !no-underline p-2 text-sm/6 font-semibold border-l-2 border-transparent',
                      urlMatchRoute(subItem.url!) ? 'bg-[var(--mdninja-background)] brightness-[0.97] text-[var(--mdninja-accent)] border-l-[var(--mdninja-accent)] rounded-l-xs' : '']">
                      {{ subItem.label }}
                    </PLink>
                  </li>
                </DisclosurePanel>
              </Disclosure>
            </li>
          </ul>
        </li>
      </ul>
    </nav>
    <div class="fixed bottom-[15px]">
      <p class="inline w-full text-gray-400 font-light">
        Powered by&nbsp;
        <a href="https://markdown.ninja" target="_blank" rel="noopener" class="text-gray-500">
          Markdown Ninja
        </a>
      </p>
    </div>
  </div>
</template>

<script lang="ts" setup>
import { useStore } from '@/app/store';
import PLink from './p_link.vue';
import { useRoute } from 'vue-router';
import { Disclosure, DisclosureButton, DisclosurePanel } from '@headlessui/vue'
import { ChevronRightIcon } from '@heroicons/vue/24/outline';

// props

// events

// composables
const $store = useStore();
const $route = useRoute();

// lifecycle

// variables

// computed

// watch

// functions
function urlMatchRoute(url: string) {
  return $route.path === url;
}
</script>
