import { useId } from "react";

// one side of the moth with its wings eye spots margin bands and antenna
function Wing() {
  return (
    <g className="logo-wing">
      <path fillRule="evenodd" d="M28 20.5C20.5 15.5 9 15 2 19.5 0.5 26 3 33 8.5 36.5 15.5 37.5 22.5 35.5 28 31ZM8.9 26a3.6 3.6 0 1 0 7.2 0a3.6 3.6 0 1 0 -7.2 0Z" />
      <path fillRule="evenodd" d="M27.5 32.5C22 35.5 14.5 38 12 43 11 50 15.5 55.5 21.5 56 26.5 53.5 29.5 47 29.5 39ZM16.4 46a3.1 3.1 0 1 0 6.2 0a3.1 3.1 0 1 0 -6.2 0Z" />
      <path d="M10.8 26a1.7 1.7 0 1 0 3.4 0a1.7 1.7 0 1 0 -3.4 0Z" />
      <path d="M18.1 46a1.4 1.4 0 1 0 2.8 0a1.4 1.4 0 1 0 -2.8 0Z" />
      <path d="M30.8 17.5C27.5 16 23.8 12 22.6 6.5 27 8.5 30.2 12.5 32 16.8Z" />
      <path className="logo-vein" d="M5.3 21.5C4.2 26 5.8 30.5 9.6 33.4M14.4 49C15.8 52 18.4 53.4 21.2 53.2M26 23.5 17.5 21M26.3 27.5 18.5 30.5" fill="none" strokeWidth="1.1" strokeLinecap="round" />
      <path className="logo-vein" d="M30.6 16.6 24.4 9.2M27.8 15.2 29.2 12.6M25.9 13 27.4 10.6M24.5 10.8 25.7 8.9" fill="none" strokeWidth="0.8" strokeLinecap="round" />
    </g>
  );
}

interface Props {
  size?: number;
  // flap keeps the wings moving and is used while data loads
  flap?: boolean;
}

// the mark is an emperor moth seen from above with a light grain so it reads as a stamp
export function Logo({ size = 28, flap = false }: Props) {
  const grain = `tm-grain-${useId().replace(/:/g, "")}`;
  return (
    <svg className={flap ? "logo is-flapping" : "logo"} width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" focusable="false">
      <filter id={grain} x="-10%" y="-10%" width="120%" height="120%">
        <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="2" seed="7" result="n" />
        <feDisplacementMap in="SourceGraphic" in2="n" scale="1" result="d" />
        <feColorMatrix in="n" type="matrix" values="0 0 0 0 0  0 0 0 0 0  0 0 0 0 0  14 0 0 0 -2.6" result="h" />
        <feComposite in="d" in2="h" operator="in" />
      </filter>
      <g filter={`url(#${grain})`} fill="currentColor">
        <Wing />
        <g transform="translate(64 0) scale(-1 1)">
          <Wing />
        </g>
        <path d="M29.2 18.2a2.8 2.8 0 1 0 5.6 0a2.8 2.8 0 1 0 -5.6 0Z" />
        <path d="M32 20.5C36 20.5 37.8 23.5 37.8 27 37.8 30 35.5 32 32 32 28.5 32 26.2 30 26.2 27 26.2 23.5 28 20.5 32 20.5Z" />
        <path d="M27.2 33.4H36.8C37.3 40 36 47 32 52.5 28 47 26.7 40 27.2 33.4Z" />
        <path className="logo-vein" d="M27.3 37.6H36.7M27.9 42H36.1M29.3 46.3H34.7" fill="none" strokeWidth="1.1" />
      </g>
    </svg>
  );
}
