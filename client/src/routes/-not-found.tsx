import { Button } from '@/components/ui/button';
import { Cat, Home } from 'lucide-react';
import { Link } from '@tanstack/react-router';

export function NotFound() {
  const codes = [100,101,102,103,200,201,202,203,204,205,206,207,208,214,226,300,301,302,303,304,305,307,308,400,401,402,403,404,405,406,407,408,409,410,411,412,413,414,415,416,417,418,419,420,421,422,423,424,425,426,428,429,431,444,450,451,495,496,497,498,499,500,501,502,503,504,506,507,508,509,510,511,521,522,523,525,530,599];
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

