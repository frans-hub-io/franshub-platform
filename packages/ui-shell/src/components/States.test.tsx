import { fireEvent, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { renderThemed } from '../test/render';
import { EmptyState, ErrorState } from './States';

describe('States', () => {
  it('shows an error with a retry button', () => {
    const onRetry = vi.fn();
    renderThemed(<ErrorState title="Could not load launches" message="The server did not answer." onRetry={onRetry} />);
    expect(screen.getByRole('alert')).toHaveTextContent('Could not load launches');
    expect(screen.getByText('The server did not answer.')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(onRetry).toHaveBeenCalledTimes(1);
  });

  it('shows an error without retry', () => {
    renderThemed(<ErrorState message="Denied" />);
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong');
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('shows an empty state with its action', () => {
    renderThemed(<EmptyState title="No launches yet" description="Run your tests to see them here." action={<button type="button">Create</button>} />);
    expect(screen.getByText('No launches yet')).toBeInTheDocument();
    expect(screen.getByText('Run your tests to see them here.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Create' })).toBeInTheDocument();
  });
});
