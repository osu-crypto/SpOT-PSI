//
// Created by bush on 12/01/18.
//

#include "utils_zp.h"

#define LEFT(X) (2*X+1)
#define RIGHT(X) (2*X+2)

void print_poly (ZZ_pX& P)
{
    long degree = deg(P);
    if (-1 == degree) {
        cout << "0";
        return;
    }
    for(long i=0; i<=degree; i++) {
        cout << coeff(P, i);
        if (i==1)
            cout << "X";
        else if(i>1)
            cout << "X^" << i;
        if (i<degree) {
            cout << " + ";
        }
    }
//    cout << endl << "random poly:" << endl << P << endl;
}

/* A recursive function to build the tree of polynomials
 * (assumming a complete binary tree => size = 2*#leafs-1
 'tree_size' is the number of nodes (including leaves) in the tree = 2*(degree+1)-1 = 2*degree+1
 'root' is the index of the subtree in the array 'tree'
 */
void build_tree (ZZ_pX* tree, ZZ_p* points, unsigned int root, unsigned int tree_size) {
    // halting condition
    if(LEFT(root)>=tree_size) {
        unsigned int point_index = root-(tree_size-1)/2;
        //setting the polynomial to be x-m where m is points[point_index]
        ZZ_p negated;
        NTL::negate(negated, points[point_index]);
        SetCoeff(tree[root], 0, negated);
        SetCoeff(tree[root], 1, 1);
//        cout << endl << "polynomial at index " << root << ":" << endl;
//        print_poly(tree[root]);
//        cout << endl;
        return;
    }

    build_tree(tree, points, LEFT(root), tree_size);
    build_tree(tree, points, RIGHT(root), tree_size);
    tree[root] = tree[LEFT(root)]*tree[RIGHT(root)];
//    cout << endl << "polynomial at index " << root << ":" << endl;
//    print_poly(tree[root]);
//    cout << endl;
}

void test_tree (ZZ_pX& final_polynomial, ZZ_p* points, unsigned int npoints) {
//    cout << "final polynomial: " << endl;
//    print_poly(final_polynomial);
//    cout << endl;
    ZZ_p result;
    bool error = false;
    for (unsigned int i=0; i<npoints; i++) {
        result = eval(final_polynomial, points[i]);
//        cout << "evaluating on " << points[i] << ": " << result << endl;
        if (0!=result) {
            cout << "FATAL ERROR: polynomials tree is incorrect!" << endl;
            error = true;
            break;
        }
    }
    if (!error)
        cout << "polynomials tree is correct." << endl;
}

/*
 * P - the polynomial to evaluate
 * tree - the subproduct tree over the x points that we want to evaluate
 * root - the current subtree
 * tree size - the size of a complete tree is 2*n-1 where n is the number of leafs
 * results - the evaluation result over the x's (that are represented by the tree)
 */
void evaluate (ZZ_pX& P, ZZ_pX* tree, unsigned int root, unsigned int tree_size, ZZ_p* results) {
    // halting condition
    if(LEFT(root)>=tree_size) {
        ZZ_pX R = P%tree[root];
//        cout << "leaf: " << root << endl; print_poly(R); cout << endl;
        if(deg(R)>0)
            cout << "ERROR: R should be constant...";
        unsigned int result_index = root-(tree_size-1)/2;
        results[result_index] = coeff(R, 0);
        return;
    }

    ZZ_pX R = P%tree[root];
    evaluate(R, tree, LEFT(root), tree_size, results);
    evaluate(R, tree, RIGHT(root), tree_size, results);
}

void test_evaluate(ZZ_pX& P, ZZ_p* points, ZZ_p* results, unsigned int npoints) {
    bool error = false;
    for (unsigned int i = 0; i < npoints; i++) {
        ZZ_p y = eval(P, points[i]);
        if (y != results[i]) {
            cout << "y=" << y << " and results[i]=" << results[i] << endl;
            error = true;
        }
    }
    if (error)
        cout << "ERROR: evaluation results do not match real evaluation!" << endl;
    else
        cout << "All evaluation results computed correctly!" << endl;
}

/*
 * expects an "empty" polynomial 'resultP'
 */
void recursive_interpolate_zp(ZZ_pX& resultP, unsigned int root, ZZ_p* x, ZZ_p* y, ZZ_p* a, ZZ_pX* M, unsigned int tree_size)
{
    // halting condition
    if(LEFT(root)>=tree_size) {
        unsigned int y_index = root-(tree_size-1)/2;
//        cout << "a: " << a[y_index];
        ZZ_p inv_a;
        inv(inv_a,a[y_index]); // inv_a = 1/a
//        cout << " inv_a: " << inv_a << endl;
        SetCoeff(resultP, 0, y[y_index]*inv_a);
        return;
    }

    ZZ_pX leftP, rightP;
    recursive_interpolate_zp(leftP, LEFT(root), x, y, a, M, tree_size);
    recursive_interpolate_zp(rightP, RIGHT(root), x, y, a, M, tree_size);

//    cout << "leftP: ";  print_poly(leftP); cout << endl;
//    cout << "rightP: "; print_poly(rightP); cout << endl;
//    cout << "M[LEFT]: "; print_poly(M[LEFT(root)]); cout << endl;
//    cout << "M[RIGHT]: "; print_poly(M[RIGHT(root)]); cout << endl;

    resultP = leftP * M[RIGHT(root)] + rightP * M[LEFT(root)] ;
//    cout << "resultP: "; print_poly(resultP); cout << endl;
}


