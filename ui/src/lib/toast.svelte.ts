import type { ToastItem } from './components/Toast.svelte';

let items = $state<ToastItem[]>([]);

export const toasts = {
  get items() { return items; },

  add(message: string, variant: ToastItem['variant'] = 'default', duration = 3500) {
    const id = crypto.randomUUID();
    items = [...items, { id, message, variant }];
    setTimeout(() => this.remove(id), duration);
    return id;
  },

  success(msg: string) { return this.add(msg, 'success'); },
  error(msg: string)   { return this.add(msg, 'danger', 5000); },

  remove(id: string) {
    items = items.filter(t => t.id !== id);
  },
};
