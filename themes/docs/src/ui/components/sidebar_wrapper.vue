<template>
  <div>
    <TransitionRoot as="template" :show="$store.sidebarOpen">
      <Dialog @click="$store.toggleSidebar(false)" class="relative z-50 md:hidden">
        <TransitionChild as="template" enter="transition-opacity ease-linear duration-300" enter-from="opacity-0" enter-to="opacity-100" leave="transition-opacity ease-linear duration-300" leave-from="opacity-100" leave-to="opacity-0">
          <div class="fixed inset-0 bg-gray-900/80" />
        </TransitionChild>

        <div class="fixed inset-0 flex">
          <TransitionChild as="template" enter="transition ease-in-out duration-300 transform" enter-from="-translate-x-full" enter-to="translate-x-0" leave="transition ease-in-out duration-300 transform" leave-from="translate-x-0" leave-to="-translate-x-full">
            <DialogPanel class="relative mr-16 flex w-full max-w-xs flex-1">
              <TransitionChild as="template" enter="ease-in-out duration-300" enter-from="opacity-0" enter-to="opacity-100" leave="ease-in-out duration-300" leave-from="opacity-100" leave-to="opacity-0">
                <div class="absolute left-full top-0 flex w-16 justify-center pt-5">
                  <button type="button" @click="$store.toggleSidebar(false)" class="-m-2.5 p-2.5 bg-[var(--mdninja-background)] text-[var(--mdninja-text)]">
                    <span class="sr-only">Close sidebar</span>
                    <XMarkIcon class="h-6 w-6" aria-hidden="true" />
                  </button>
                </div>
              </TransitionChild>
              <slot />
            </DialogPanel>
          </TransitionChild>
        </div>
      </Dialog>
    </TransitionRoot>


    <!-- desktop sidebar -->
    <div :class="[$store.announcement ? 'mt-12' : '', 'hidden md:fixed md:inset-y-0 md:z-10 md:flex md:w-64 md:flex-col border-r']">
      <slot />
    </div>
  </div>
</template>

<script lang="ts" setup>
import { XMarkIcon } from '@heroicons/vue/24/outline'
import { Dialog, DialogPanel, TransitionChild, TransitionRoot } from '@headlessui/vue'
import { useStore } from '@/app/store';

// props

// events

// composables
const $store = useStore();

// lifecycle

// variables

// computed

// watch

// functions
</script>
