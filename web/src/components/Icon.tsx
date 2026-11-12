import type { ReactNode } from "react";

const PATHS: Record<string, ReactNode> = {
  heart: <path d="M12 20s-7-4.4-7-10a4 4 0 0 1 7-2.6A4 4 0 0 1 19 10c0 5.6-7 10-7 10Z" />,
  comment: <path d="M5 5h14v11H10l-5 4V5Z" />,
  external: <path d="M9 6h9v9M18 6 7 17" />,
};

interface Props {
  name: keyof typeof PATHS;
  size?: number;
  filled?: boolean;
}

export function Icon({ name, size = 18, filled = false }: Props) {
  return (
    <svg
      className="icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill={filled ? "currentColor" : "none"}
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {PATHS[name]}
    </svg>
  );
}
