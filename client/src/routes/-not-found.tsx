
/**
 * FILE: -not-found.tsx
 *
 * ROLE:
 *      Custom fallback page for undefined or invalid routes.
 *
 * PURPOSE:
 *      Provides a user-friendly and non-technical response when a user
 *      navigates to a route that does not exist in the application.
 *
 * DESIGN CHOICE:
 *      Uses humor (random HTTP status cat images) to soften the error
 *      experience while still clearly indicating that the page was not found.
 *
 *  NOTES:
 *  - No sensitive data is accessed or displayed.
 *  - No authentication or authorization logic is involved.
 *  - This page is safe to expose publicly.
 */
import { Button } from '@/components/ui/button';
import { Cat, Home } from 'lucide-react';
import { Link } from '@tanstack/react-router';

/**
 * FUNCTION: NotFound
 *
 * PURPOSE:
 *      Renders a fallback UI when the user navigates to an unknown route.
 *
 * FLOW:
 *  1) Selects a random HTTP status code from a predefined list.
 *  2) Displays a corresponding image from http.cat.
 *  3) Shows a short explanatory message to the user.
 *
 * UX NOTES:
 *  - Keeps tone light to reduce frustration.
 *  - Avoids exposing internal routing or server details.
 */
export function NotFound() {

  /**
   * list of HTTP status codes used to fetch a random  image from http.cat.
   *
   *  - Includes both client-side and server-side error codes.
   *  - Used purely for visual feedback, not for logic.
   */
  const codes = [100,101,102,103,200,201,202,203,204,205,206,207,208,214,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,419,420,421,422,423,424,425,426,428,429,431,444,450,451,495,496,497,498,499,500,501,502,503,504,506,507,508,509,510,511,521,522,523,525,530,599];
  
  //Randomly select an HTTP status code to display.
  const randomCode = codes[Math.floor(Math.random() * codes.length)];

  return (
<div className="flex flex-col items-center justify-center bg-gray-50 text-center px-4 py-8">
      <img 
        src={`https://http.cat/${randomCode}`} 
        alt={`HTTP ${randomCode} cat`} 
        className="rounded-lg shadow-md mb-8 max-w-md"
      />
      <p className="text-xl text-gray-600 mb-8">Oops! Page not found. But here's some cuteness to cheer you up.</p>
    </div>
  );
}

