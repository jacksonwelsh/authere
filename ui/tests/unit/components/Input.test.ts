import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/svelte';
import userEvent from '@testing-library/user-event';
import Input from '../../../src/lib/components/Input.svelte';

describe('Input', () => {
  it('renders label wired to the input via for/id', () => {
    render(Input, { props: { label: 'Username' } });
    const input = screen.getByLabelText('Username');
    expect(input.tagName).toBe('INPUT');
  });

  it('fires oninput callback with the latest value', async () => {
    const oninput = vi.fn();
    render(Input, { props: { label: 'Name', oninput } });
    await userEvent.type(screen.getByLabelText('Name'), 'ab');
    expect(oninput).toHaveBeenLastCalledWith('ab');
  });

  it('fires onblur when focus leaves the input', async () => {
    const onblur = vi.fn();
    render(Input, { props: { label: 'Invite', onblur } });
    const input = screen.getByLabelText('Invite');
    input.focus();
    input.blur();
    expect(onblur).toHaveBeenCalled();
  });

  it('renders error message and marks the field as errored', () => {
    const { container } = render(Input, {
      props: { label: 'Email', error: 'Invalid email' },
    });
    expect(screen.getByText('Invalid email')).toBeInTheDocument();
    expect(container.querySelector('.field.has-error')).not.toBeNull();
  });

  it('disables the input when disabled=true', () => {
    render(Input, { props: { label: 'X', disabled: true } });
    expect(screen.getByLabelText('X')).toBeDisabled();
  });
});
