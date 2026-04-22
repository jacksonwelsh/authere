import { describe, it, expect } from 'vitest';
import { render, screen, within } from '@testing-library/svelte';
import { createRawSnippet } from 'svelte';
import ResponsiveTable from '../../../src/lib/components/ResponsiveTable.svelte';

interface Row {
  id: string;
  name: string;
  username: string;
}

const columns = [
  { key: 'name',     label: 'Name' },
  { key: 'username', label: 'Username' },
];

const items: Row[] = [
  { id: 'u1', name: 'Alice Smith', username: 'alice' },
  { id: 'u2', name: 'Bob Jones',   username: 'bob' },
];

// Svelte compiles snippets into generated JS, but createRawSnippet lets us hand-roll
// one for test fixtures. The signature matches <cell({ item, column })>.
const cellSnippet = createRawSnippet<[{ item: Row; column: { key: string; label: string } }]>(
  (getArgs) => ({
    render: () => {
      const { item, column } = getArgs();
      return `<span>${(item as any)[column.key]}</span>`;
    },
  }),
);

const actionsSnippet = createRawSnippet<[{ item: Row }]>((getArgs) => ({
  render: () => {
    const { item } = getArgs();
    return `<button type="button" class="btn" data-testid="edit-${item.id}">Edit</button>`;
  },
}));

const emptySnippet = createRawSnippet(() => ({
  render: () => '<span>No rows here.</span>',
}));

describe('ResponsiveTable', () => {
  it('renders a column header and one row per item in table mode', () => {
    render(ResponsiveTable, {
      props: {
        columns,
        items,
        getKey: (r: Row) => r.id,
        label: 'Users',
        cell: cellSnippet,
      },
    });

    // Column headers.
    expect(screen.getByRole('columnheader', { name: 'Name' })).toBeInTheDocument();
    expect(screen.getByRole('columnheader', { name: 'Username' })).toBeInTheDocument();

    // One row per item.
    expect(screen.getByTestId('row-u1')).toBeInTheDocument();
    expect(screen.getByTestId('row-u2')).toBeInTheDocument();
    expect(within(screen.getByTestId('row-u1')).getByText('Alice Smith')).toBeInTheDocument();
  });

  it('renders cards mirroring the table rows for the mobile layout', () => {
    render(ResponsiveTable, {
      props: {
        columns,
        items,
        getKey: (r: Row) => r.id,
        label: 'Users',
        cell: cellSnippet,
      },
    });

    // Both variants are in the DOM — CSS media query controls which is visible.
    expect(screen.getByTestId('card-u1')).toBeInTheDocument();
    expect(screen.getByTestId('card-u2')).toBeInTheDocument();
    const card = screen.getByTestId('card-u1');
    // Each card includes the column label + value.
    expect(within(card).getByText('Name')).toBeInTheDocument();
    expect(within(card).getByText('Alice Smith')).toBeInTheDocument();
  });

  it('renders the empty snippet when items is empty', () => {
    render(ResponsiveTable, {
      props: {
        columns,
        items: [] as Row[],
        getKey: (r: Row) => r.id,
        cell: cellSnippet,
        empty: emptySnippet,
      },
    });
    // Empty state renders in both variants.
    expect(screen.getAllByText('No rows here.').length).toBeGreaterThan(0);
  });

  it('renders per-row actions when the actions snippet is provided', () => {
    render(ResponsiveTable, {
      props: {
        columns,
        items,
        getKey: (r: Row) => r.id,
        cell: cellSnippet,
        actions: actionsSnippet,
      },
    });
    // Desktop table shows the action inline for every row.
    expect(screen.getByTestId('edit-u1')).toBeInTheDocument();
    expect(screen.getByTestId('edit-u2')).toBeInTheDocument();
    // Mobile card variant collapses actions behind an overflow trigger per row.
    expect(screen.getAllByTestId('action-menu-trigger').length).toBe(2);
  });

  it('suppresses the actions slot for rows where hasActions returns false', () => {
    render(ResponsiveTable, {
      props: {
        columns,
        items,
        getKey: (r: Row) => r.id,
        cell: cellSnippet,
        actions: actionsSnippet,
        hasActions: (r: Row) => r.id !== 'u2',
      },
    });
    // u1's inline table action renders; u2's does not.
    expect(screen.getByTestId('edit-u1')).toBeInTheDocument();
    expect(screen.queryByTestId('edit-u2')).not.toBeInTheDocument();
    // Only u1's card exposes an overflow trigger.
    expect(screen.getAllByTestId('action-menu-trigger').length).toBe(1);
  });
});
