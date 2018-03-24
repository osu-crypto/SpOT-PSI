//
// Created by bush on 13/01/18.
//

#include "tests_zp.h"
#include "zp.h"

//void multipoint_evaluate_zp(ZZ_pX& P, ZZ_p* x, ZZ_p* y, long degree)
//{
//    // we want to evaluate P on 'degree+1' values.
//    ZZ_pX* p_tree = new ZZ_pX[degree*2+1];
//    steady_clock::time_point begin1 = steady_clock::now();
//    build_tree (p_tree, x, 0, degree*2+1);
//    steady_clock::time_point end1 = steady_clock::now();
////    test_tree(p_tree[0], x, degree+1);
//
//    steady_clock::time_point begin2 = steady_clock::now();
//    evaluate(P, p_tree, 0, degree*2+1, y);
//    chrono::steady_clock::time_point end2 = steady_clock::now();
////    test_evaluate(P,x,y,degree+1);
//
//    cout << "Building tree: " << duration_cast<milliseconds>(end1 - begin1).count() << " ms" << endl;
//    cout << "Evaluating points: " << duration_cast<milliseconds>(end2 - begin2).count() << " ms" << endl;
//    cout << "Total: " << duration_cast<milliseconds>(end1 - begin1).count()+ duration_cast<milliseconds>(end2 - begin2).count() << " ms" << endl;
//}

//void test_multipoint_eval_zp(ZZ prime, long degree)
//{
//    // init underlying prime field
//    ZZ_p::init(ZZ(prime));
//
//    // the given polynomial
//    ZZ_pX P;
//    random(P, degree+1);
//    SetCoeff(P,degree,random_ZZ_p());
//
//    // evaluation points:
//    ZZ_p* x = new ZZ_p[degree+1];
//    ZZ_p* y = new ZZ_p[degree+1];
//
//    for(unsigned int i=0;i<=degree; i++) {
//        random(x[i]);
//    }
//
//    multipoint_evaluate_zp(P, x, y, degree);
//
///* This is moved to the evaluation function
////    // we want to evaluate P on 'degree+1' values.
////    ZZ_pX* p_tree = new ZZ_pX[degree*2+1];
////    steady_clock::time_point begin1 = steady_clock::now();
////    build_tree (p_tree, x, 0, degree*2+1);
////    steady_clock::time_point end1 = steady_clock::now();
//////    test_tree(p_tree[0], x, DEGREE+1);
////
////    steady_clock::time_point begin2 = steady_clock::now();
////    evaluate(P, p_tree, 0, degree*2+1, y);
////    chrono::steady_clock::time_point end2 = steady_clock::now();
//////    test_evaluate(P,x,y,DEGREE+1);
////
////    cout << "Building tree: " << duration_cast<milliseconds>(end1 - begin1).count() << " ms" << endl;
////    cout << "Evaluating points: " << duration_cast<milliseconds>(end2 - begin2).count() << " ms" << endl;
////    cout << "Total: " << duration_cast<milliseconds>(end1 - begin1).count()+ duration_cast<milliseconds>(end2 - begin2).count() << " ms" << endl;
// */
//}

//
///*
// * We follow the algorithm and notation as in Moneck & Borodin '73
// */
//void interpolate_zp(ZZ_pX& resultP, ZZ_p* x, ZZ_p* y, long degree)
//{
//    system_clock::time_point begin[4];
//    system_clock::time_point end[4];
//
//    //we first build the tree of the super moduli
//    ZZ_pX* M = new ZZ_pX[degree*2+1];
//    begin[1]= system_clock::now();
//    build_tree(M,x,0, degree*2+1);
//    end[1] = system_clock::now();
////    test_tree(M[0], x, degree+1);
//
//    //we construct a preconditioned global structure for the a_k for all 1<=k<=(degree+1)
//    ZZ_p* a = new ZZ_p[degree+1];
//    ZZ_pX d;
//    begin[2] = system_clock::now();
//    diff(d, M[0]);
//    end[2] = system_clock::now();
////    cout << "M(x):" << endl; print_poly(M[0]);   cout << endl;
////    cout << "d(x):" << endl; print_poly(d);   cout << endl;
//
//    //evaluate d(x) to obtain the results in the array a
//    begin[3] = system_clock::now();
//    evaluate(d, M, 0, degree*2+1, a);
//    end[3] = system_clock::now();
////    multipoint_evaluate_zp(d, x, a, degree);
////    for (int i=0; i<degree+1; i++) {
////        cout << "a[" << i << "] = " << a[i] << endl;
////    }
//
//    //now we can apply the recursive formula
//    begin[4] = system_clock::now();
//    recursive_interpolate_zp(resultP, 0, x, y, a, M, degree*2+1);
//    end[4] = system_clock::now();
////    cout << "resultP: "; print_poly(resultP); cout << endl;
//
//    cout << "Building tree: " << duration_cast<milliseconds>(end[1] - begin[1]).count() << " ms" << endl;
//    cout << "Differentiate: " << duration_cast<milliseconds>(end[2] - begin[2]).count() << " ms" << endl;
//    cout << "Evaluate diff: " << duration_cast<milliseconds>(end[3] - begin[3]).count() << " ms" << endl;
//    cout << "Interpolation: " << duration_cast<milliseconds>(end[4] - begin[4]).count() << " ms" << endl;
//    cout << "Total: " << duration_cast<milliseconds>(end[1]-begin[1] + end[2]-begin[2] + end[3]-begin[3] + end[4]-begin[4]).count() << " ms" << endl;
//}

void test_interpolate_zp(ZZ prime, long degree)
{
    // init underlying prime field
    ZZ_p::init(ZZ(prime));

    // interpolation points:
    ZZ_p* x = new ZZ_p[degree+1];
    ZZ_p* y = new ZZ_p[degree+1];
    for(unsigned int i=0;i<=degree; i++) {
        random(x[i]);
        random(y[i]);
//        cout << "(" << x[i] << "," << y[i] << ")" << endl;
    }

    ZZ_pX P;
    interpolate_zp(P, x, y, degree);
//    cout << "P: "; print_poly(P); cout << endl;
//    test_interpolation_result_zp(P, x, y, degree);
}

void test_interpolation_result_zp(ZZ_pX& P, ZZ_p* x, ZZ_p* y, long degree)
{
    cout << "Testing result polynomial" << endl;
    ZZ_p res;
    for (long i=0; i< degree+1; i++) {
        eval(res, P, x[i]);
        if (res != y[i]) {
            cout << "Error! x = " << x[i] << ", y = " << y[i] << ", res = " << res << endl;
            return;
        }
    }
    cout << "Polynomial is interpolated correctly!" << endl;
}