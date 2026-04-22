import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/svelte';
import { createRawSnippet } from 'svelte';
import Badge from '../../../src/lib/components/Badge.svelte';

const text = (label: string) =>
  createRawSnippet(() => ({ render: () => `<span>${label}</span>` }));

describe('Badge', () => {
  it('uses the default variant when none is supplied', () => {
    const { container } = render(Badge, { props: { children: text('plain') } });
    expect(container.querySelector('.badge-default')).not.toBeNull();
  });

  it.each(['success', 'warning', 'danger', 'accent'] as const)(
    'applies variant class for %s',
    (variant) => {
      const { container } = render(Badge, {
        props: { variant, children: text(variant) },
      });
      expect(container.querySelector(`.badge-${variant}`)).not.toBeNull();
    },
  );
});
