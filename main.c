/*
 *     main.c - Contains the main routine
 *     Copyright (C) 2016  Sk. Mohammadul Haque
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "exeknow.h"

int main(int argc, char* argv[])
{
    if(argc<2)
    {
        fprintf(stderr, "Bad number of parameters.\n");
        exit(1);
    }
    exeknow_know(argv[1]);
    return 0;
}
